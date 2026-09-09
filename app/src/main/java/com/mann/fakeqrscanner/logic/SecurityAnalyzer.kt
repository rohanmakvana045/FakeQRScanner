package com.mann.fakeqrscanner.logic

import java.net.URI
import java.util.Locale

/**
 * SecurityAnalyzer performs heuristic-based risk analysis on QR code payloads.
 *
 * It does NOT access the network, open URLs, or rely on any external API during analysis.
 * A reputation API (e.g. Google Safe Browsing, VirusTotal) can be integrated later
 * by adding an asynchronous check and merging the result into the score.
 *
 * Scoring: 0-100
 *   0-29  = LOW RISK  (labelled "LOW RISK")
 *   30-59 = SUSPICIOUS (labelled "SUSPICIOUS")
 *   60-100 = HIGH RISK  (labelled "HIGH RISK")
 *
 * IMPORTANT: HTTPS alone does NOT make a URL safe.
 *            No domain is hardcoded as "safe".
 */
object SecurityAnalyzer {

    // ── Data class returned to callers ──────────────────────────────────
    data class AnalysisResult(
        val riskScore: Int,
        val riskLevel: String,
        val riskLabel: String,
        val indicators: List<String>,
        val domain: String,
        val isHttps: Boolean?,
        val isUrl: Boolean,
        val contentType: String,         // e.g. "URL", "Plain Text", "Wi-Fi Config", etc.
        val recommendedAction: String
    )

    // ── Known URL-shortener domains ────────────────────────────────────
    private val SHORTENER_DOMAINS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly",
        "is.gd", "buff.ly", "ow.ly", "tiny.cc", "lnkd.in",
        "db.tt", "qr.ae", "adf.ly", "sh.st", "git.io", "linktr.ee",
        "cutt.ly", "shorturl.at", "rb.gy", "v.gd", "clck.ru",
        "trib.al", "soo.gd", "s.id"
    )

    // ── Suspicious keywords — used only as ONE of many signals ────────
    private val SUSPICIOUS_KEYWORDS = setOf(
        "login", "signin", "verify", "password", "credential",
        "billing", "account", "update", "secure", "confirm",
        "suspend", "unlock", "expire", "urgent", "alert"
    )

    // ── Phishing bait keywords (stronger signal) ─────────────────────
    private val PHISHING_BAIT_KEYWORDS = setOf(
        "free-gift", "winner", "prize", "lottery", "claim-now",
        "act-now", "limited-offer", "congratulations", "you-won"
    )

    // ── Suspicious TLDs commonly abused ──────────────────────────────
    private val SUSPICIOUS_TLDS = setOf(
        "tk", "ml", "ga", "cf", "gq",      // Freenom free TLDs
        "buzz", "xyz", "top", "club",
        "work", "click", "link", "surf",
        "icu", "cam", "rest"
    )

    // ── Suspicious port numbers ──────────────────────────────────────
    private val SUSPICIOUS_PORTS = setOf(
        8080, 8443, 8888, 9090, 4443, 1337, 31337, 6666, 6667
    )

    // ── IP address pattern ───────────────────────────────────────────
    private val IP_PATTERN = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")

    // ── Brand-impersonation fragments ────────────────────────────────
    private val BRAND_FRAGMENTS = setOf(
        "paypal", "apple", "google", "microsoft", "amazon", "netflix",
        "facebook", "instagram", "whatsapp", "telegram", "banking",
        "chase", "wellsfargo", "citibank", "hsbc", "barclays"
    )

    // ════════════════════════════════════════════════════════════════════
    // Main entry point
    // ════════════════════════════════════════════════════════════════════
    fun analyze(input: String?): AnalysisResult {
        if (input.isNullOrBlank()) {
            return AnalysisResult(
                riskScore = 0,
                riskLevel = "LOW RISK",
                riskLabel = "No content to analyze",
                indicators = listOf("No content provided"),
                domain = "N/A",
                isHttps = null,
                isUrl = false,
                contentType = "Empty",
                recommendedAction = "No action required."
            )
        }

        // Prevent Regex StackOverflow on massive fuzzed/fake QR payloads
        val trimmedInput = input.trim().take(10_000)

        // ── Detect content type ───────────────────────────────────────
        return when {
            isWifiConfig(trimmedInput)  -> analyzeWifi(trimmedInput)
            isPhoneNumber(trimmedInput) -> analyzePhone(trimmedInput)
            isEmailLink(trimmedInput)   -> analyzeEmail(trimmedInput)
            checkIfUrl(trimmedInput)    -> analyzeUrl(trimmedInput)
            else                        -> analyzePlainText(trimmedInput)
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // Content-type detectors
    // ════════════════════════════════════════════════════════════════════
    private fun isWifiConfig(input: String): Boolean =
        input.startsWith("WIFI:", ignoreCase = true)

    private fun isPhoneNumber(input: String): Boolean =
        input.startsWith("tel:", ignoreCase = true) ||
                Regex("""^\+?\d[\d\-\s()]{6,15}$""").matches(input)

    private fun isEmailLink(input: String): Boolean =
        input.startsWith("mailto:", ignoreCase = true) ||
                input.startsWith("MATMSG:", ignoreCase = true)

    private fun checkIfUrl(input: String): Boolean {
        if (input.startsWith("http://", ignoreCase = true) ||
            input.startsWith("https://", ignoreCase = true)
        ) return true
        val urlRegex = Regex("""^(?i)([a-z0-9]+([\-.][a-z0-9]+)*\.[a-z]{2,63})(:[0-9]{1,5})?(/.*)?$""")
        return urlRegex.matches(input) || input.contains(Regex("""\.[a-zA-Z]{2,63}(/|$)"""))
    }

    // ════════════════════════════════════════════════════════════════════
    // Wi-Fi config analysis
    // ════════════════════════════════════════════════════════════════════
    private fun analyzeWifi(input: String): AnalysisResult {
        val indicators = mutableListOf<String>()
        var score = 0

        indicators.add("Content type: Wi-Fi network configuration")

        // Check for open (no-password) networks
        if (input.contains("T:nopass", ignoreCase = true) || !input.contains("P:", ignoreCase = true)) {
            score += 25
            indicators.add("Open network: No password required — data may be intercepted")
        }

        // Check for WEP (weak encryption)
        if (input.contains("T:WEP", ignoreCase = true)) {
            score += 20
            indicators.add("Weak encryption: Uses WEP which is easily cracked")
        }

        // Hidden SSID
        if (input.contains("H:true", ignoreCase = true)) {
            score += 10
            indicators.add("Hidden SSID: Network name is not broadcast")
        }

        if (indicators.size == 1) {
            indicators.add("No obvious threats detected in Wi-Fi configuration")
        }

        val finalScore = score.coerceIn(0, 100)
        return AnalysisResult(
            riskScore = finalScore,
            riskLevel = getRiskLevel(finalScore),
            riskLabel = getRiskLabel(finalScore),
            indicators = indicators,
            domain = "N/A",
            isHttps = null,
            isUrl = false,
            contentType = "Wi-Fi Configuration",
            recommendedAction = getRecommendedAction(finalScore, false)
        )
    }

    // ════════════════════════════════════════════════════════════════════
    // Phone number analysis
    // ════════════════════════════════════════════════════════════════════
    private fun analyzePhone(input: String): AnalysisResult {
        val indicators = mutableListOf<String>()
        var score = 5  // small base — phone QR codes are generally benign

        indicators.add("Content type: Phone number")

        // Premium rate numbers (very simplified check)
        val cleaned = input.replace(Regex("[^0-9+]"), "")
        if (cleaned.startsWith("+44870") || cleaned.startsWith("+44871") ||
            cleaned.startsWith("+44900") || cleaned.startsWith("+1900")
        ) {
            score += 35
            indicators.add("Premium-rate number detected — calls may incur high charges")
        }

        if (indicators.size == 1) {
            indicators.add("No obvious threats detected")
        }

        val finalScore = score.coerceIn(0, 100)
        return AnalysisResult(
            riskScore = finalScore,
            riskLevel = getRiskLevel(finalScore),
            riskLabel = getRiskLabel(finalScore),
            indicators = indicators,
            domain = "N/A",
            isHttps = null,
            isUrl = false,
            contentType = "Phone Number",
            recommendedAction = getRecommendedAction(finalScore, false)
        )
    }

    // ════════════════════════════════════════════════════════════════════
    // Email link analysis
    // ════════════════════════════════════════════════════════════════════
    private fun analyzeEmail(input: String): AnalysisResult {
        val indicators = mutableListOf<String>()
        var score = 5

        indicators.add("Content type: Email link")

        // Check for suspicious subject/body pre-fill
        val lower = input.lowercase(Locale.getDefault())
        val suspiciousEmail = SUSPICIOUS_KEYWORDS.filter { lower.contains(it) }
        if (suspiciousEmail.isNotEmpty()) {
            score += (suspiciousEmail.size * 8).coerceAtMost(25)
            indicators.add("Pre-filled email contains suspicious keywords: ${suspiciousEmail.joinToString(", ")}")
        }

        if (indicators.size == 1) {
            indicators.add("No obvious threats detected")
        }

        val finalScore = score.coerceIn(0, 100)
        return AnalysisResult(
            riskScore = finalScore,
            riskLevel = getRiskLevel(finalScore),
            riskLabel = getRiskLabel(finalScore),
            indicators = indicators,
            domain = "N/A",
            isHttps = null,
            isUrl = false,
            contentType = "Email Link",
            recommendedAction = getRecommendedAction(finalScore, false)
        )
    }

    // ════════════════════════════════════════════════════════════════════
    // Plain text analysis
    // ════════════════════════════════════════════════════════════════════
    private fun analyzePlainText(input: String): AnalysisResult {
        val indicators = mutableListOf<String>()
        var score = 0

        // Suspicious keywords in text
        val foundWords = SUSPICIOUS_KEYWORDS.filter { input.contains(it, ignoreCase = true) }
        if (foundWords.isNotEmpty()) {
            score += (foundWords.size * 10).coerceAtMost(25)
            indicators.add("Contains keywords sometimes associated with social engineering: ${foundWords.joinToString(", ")}")
        }

        // Credit card-like number
        if (input.contains(Regex("""\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"""))) {
            score += 40
            indicators.add("Contains a numeric pattern resembling a credit card number")
        }

        // SSN-like pattern
        if (input.contains(Regex("""\b\d{3}-\d{2}-\d{4}\b"""))) {
            score += 35
            indicators.add("Contains a pattern resembling a Social Security Number")
        }

        if (indicators.isEmpty()) {
            indicators.add("No suspicious text patterns detected")
        }

        val finalScore = score.coerceIn(0, 100)
        return AnalysisResult(
            riskScore = finalScore,
            riskLevel = getRiskLevel(finalScore),
            riskLabel = getRiskLabel(finalScore),
            indicators = indicators,
            domain = "N/A",
            isHttps = null,
            isUrl = false,
            contentType = "Plain Text",
            recommendedAction = getRecommendedAction(finalScore, false)
        )
    }

    // ════════════════════════════════════════════════════════════════════
    // URL analysis — the core of the security engine
    // ════════════════════════════════════════════════════════════════════
    private fun analyzeUrl(input: String): AnalysisResult {
        val indicators = mutableListOf<String>()
        var score = 0

        // ── Parse URL ─────────────────────────────────────────────────
        val hasProtocol = input.startsWith("http://", ignoreCase = true) ||
                input.startsWith("https://", ignoreCase = true)
        val urlString = if (!hasProtocol) "http://$input" else input

        val uri = try { URI(urlString) } catch (_: Exception) { null }

        val isHttps = when {
            uri != null && hasProtocol -> input.startsWith("https://", ignoreCase = true)
            uri != null -> null   // protocol was not specified by user
            else -> null
        }

        val rawDomain = uri?.host ?: extractDomainFallback(input)
        val domain = rawDomain.lowercase(Locale.getDefault())
        val path = uri?.path.orEmpty().lowercase(Locale.getDefault())
        val query = uri?.query.orEmpty().lowercase(Locale.getDefault())
        val port = uri?.port ?: -1
        val fullLower = input.lowercase(Locale.getDefault())

        // ── 1. Protocol check ─────────────────────────────────────────
        if (isHttps == false) {
            score += 15
            indicators.add("Insecure Connection: Uses HTTP instead of HTTPS — data is transmitted unencrypted")
        } else if (isHttps == true) {
            // HTTPS is present — but it is NOT a guarantee of trust
            indicators.add("HTTPS: Connection is encrypted, but this alone does not prove the site is trustworthy")
        }

        // ── 2. IP-address based URL ───────────────────────────────────
        if (IP_PATTERN.matches(domain)) {
            score += 30
            indicators.add("IP-based URL: Uses a direct IP address ($domain) instead of a domain name — common in phishing")
        }

        // ── 3. Punycode / IDN homograph attack ────────────────────────
        if (domain.contains("xn--")) {
            score += 25
            indicators.add("Internationalized Domain (Punycode): Domain uses non-ASCII characters that may visually mimic a legitimate domain")
        }

        // ── 4. URL shortener ──────────────────────────────────────────
        if (!IP_PATTERN.matches(domain)) {
            if (SHORTENER_DOMAINS.contains(domain) || SHORTENER_DOMAINS.any { domain.endsWith(".$it") }) {
                score += 20
                indicators.add("URL Shortener: Uses a known link-shortening service ($domain) which hides the final destination")
            }
        }

        // ── 5. Excessive subdomains ───────────────────────────────────
        if (!IP_PATTERN.matches(domain)) {
            val parts = domain.split('.')
            if (parts.size > 4) {
                score += 15
                indicators.add("Subdomain Abuse: Has ${parts.size - 2} subdomains — often used to impersonate legitimate sites")
            } else if (parts.size == 4) {
                score += 5
                indicators.add("Multiple Subdomains: Domain has ${parts.size - 2} subdomains")
            }
        }

        // ── 6. Suspicious TLD ─────────────────────────────────────────
        val tld = domain.substringAfterLast('.', "")
        if (SUSPICIOUS_TLDS.contains(tld)) {
            score += 10
            indicators.add("Suspicious TLD: The .$tld top-level domain is frequently associated with abuse")
        }

        // ── 7. Suspicious port ────────────────────────────────────────
        if (port > 0 && port != 80 && port != 443) {
            if (SUSPICIOUS_PORTS.contains(port)) {
                score += 20
                indicators.add("Suspicious Port: Uses non-standard port $port, which is unusual for legitimate websites")
            } else {
                score += 10
                indicators.add("Non-Standard Port: Uses port $port instead of standard 80/443")
            }
        }

        // ── 8. Suspicious keywords in URL path/query ──────────────────
        val pathAndQuery = "$path $query"
        val foundKeywords = SUSPICIOUS_KEYWORDS.filter { pathAndQuery.contains(it) }
        if (foundKeywords.isNotEmpty()) {
            // Only add score based on count — this is ONE signal, not definitive
            val kwScore = (foundKeywords.size * 5).coerceAtMost(15)
            score += kwScore
            indicators.add("Suspicious Path Keywords: URL path/query contains: ${foundKeywords.joinToString(", ")}")
        }

        // ── 9. Phishing bait keywords ─────────────────────────────────
        val foundBait = PHISHING_BAIT_KEYWORDS.filter { fullLower.contains(it) }
        if (foundBait.isNotEmpty()) {
            score += (foundBait.size * 10).coerceAtMost(25)
            indicators.add("Phishing Bait: Contains lure keywords: ${foundBait.joinToString(", ")}")
        }

        // ── 10. Brand impersonation in domain ─────────────────────────
        if (!IP_PATTERN.matches(domain)) {
            val domainBase = domain.substringBeforeLast('.').substringBeforeLast('.')
            val matchedBrands = BRAND_FRAGMENTS.filter { brand ->
                domainBase.contains(brand) && !domain.endsWith(".$brand.com") && !domain.endsWith(".$brand.org")
            }
            if (matchedBrands.isNotEmpty()) {
                score += 20
                indicators.add("Possible Brand Impersonation: Domain contains brand name(s) [${matchedBrands.joinToString(", ")}] but does not appear to be the official domain")
            }
        }

        // ── 11. '@' in URL (user-info spoofing) ──────────────────────
        if (input.contains("@")) {
            score += 25
            indicators.add("User-Info Spoofing: Contains '@' which can hide the real destination (e.g. google.com@evil.com goes to evil.com)")
        }

        // ── 12. Excessive hyphens in domain ──────────────────────────
        val domainHyphens = domain.count { it == '-' }
        if (domainHyphens > 4) {
            score += 10
            indicators.add("Excessive Hyphens: Domain contains $domainHyphens hyphens — common in brand-spoofing domains")
        } else if (domainHyphens > 2) {
            score += 5
            indicators.add("Multiple Hyphens: Domain contains $domainHyphens hyphens")
        }

        // ── 13. Excessively long URL ──────────────────────────────────
        if (input.length > 150) {
            score += 15
            indicators.add("Excessive Length: URL is very long (${input.length} chars) — may be used to conceal the true destination")
        } else if (input.length > 100) {
            score += 5
            indicators.add("Long URL: ${input.length} characters")
        }

        // ── 14. Multiple protocol prefixes (nested redirect) ─────────
        val protocolCount = Regex("https?://", RegexOption.IGNORE_CASE).findAll(input).count()
        if (protocolCount > 1) {
            score += 20
            indicators.add("Embedded Redirect: Contains $protocolCount protocol prefixes — may be a redirect or open-redirect exploit")
        }

        // ── 15. Percent-encoded characters ────────────────────────────
        val encodedCount = Regex("%[0-9A-Fa-f]{2}").findAll(input).count()
        if (encodedCount > 5) {
            score += 15
            indicators.add("Heavy Encoding: Contains $encodedCount percent-encoded characters — may be obfuscating content")
        } else if (encodedCount > 0) {
            score += 5
            indicators.add("URL Encoding: Contains $encodedCount percent-encoded character(s)")
        }

        // ── 16. Data URI / javascript URI ─────────────────────────────
        if (fullLower.startsWith("data:") || fullLower.startsWith("javascript:")) {
            score += 40
            indicators.add("Dangerous Scheme: Uses '${input.substringBefore(':')}:' scheme which can execute code or embed malicious content")
        }

        // ── If no suspicious indicators were found ────────────────────
        if (indicators.size <= 1) {
            // Only the HTTPS note or nothing — add a neutral observation
            indicators.add("No obvious threats detected, but this does not guarantee the site is safe")
        }

        val finalScore = score.coerceIn(0, 100)
        return AnalysisResult(
            riskScore = finalScore,
            riskLevel = getRiskLevel(finalScore),
            riskLabel = getRiskLabel(finalScore),
            indicators = indicators,
            domain = domain.ifEmpty { "N/A" },
            isHttps = isHttps,
            isUrl = true,
            contentType = "URL",
            recommendedAction = getRecommendedAction(finalScore, true)
        )
    }

    // ════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════

    private fun extractDomainFallback(input: String): String {
        var clean = input.replace(Regex("(?i)^https?://"), "")
        val slashIdx = clean.indexOf('/')
        if (slashIdx != -1) clean = clean.substring(0, slashIdx)
        val colonIdx = clean.indexOf(':')
        if (colonIdx != -1) clean = clean.substring(0, colonIdx)
        return clean
    }

    private fun getRiskLevel(score: Int): String = when (score) {
        in 0..29  -> "LOW RISK"
        in 30..59 -> "SUSPICIOUS"
        else      -> "HIGH RISK"
    }

    private fun getRiskLabel(score: Int): String = when (score) {
        in 0..29  -> "No obvious threats detected"
        in 30..59 -> "Some suspicious indicators found"
        else      -> "Strong risk indicators detected"
    }

    private fun getRecommendedAction(score: Int, isUrl: Boolean): String = when {
        score >= 60 && isUrl -> "Do NOT open this link. It exhibits strong indicators of being malicious."
        score >= 30 && isUrl -> "Exercise caution. Verify the destination before opening."
        isUrl                -> "Review the URL before proceeding. No obvious threats detected."
        score >= 60          -> "This content contains high-risk patterns. Proceed with extreme caution."
        score >= 30          -> "This content has some suspicious indicators. Review carefully."
        else                 -> "No obvious threats detected."
    }
}
