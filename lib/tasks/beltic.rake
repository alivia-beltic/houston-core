namespace :beltic do
  desc "Issue Houston's own business credential (one-time KYB bootstrap). Prints the credential_id to set as BELTIC_ORG_CREDENTIAL_ID."
  task bootstrap_business_credential: :environment do
    unless Houston::Beltic.config.configured?
      abort "BELTIC_API_KEY is not set. Configure it before bootstrapping."
    end

    if Houston::Beltic.config.org_credential_id && !Houston::Beltic.config.org_credential_id.empty?
      puts "[Beltic] BELTIC_ORG_CREDENTIAL_ID is already set: #{Houston::Beltic.config.org_credential_id}"
      puts "[Beltic] Refusing to issue a new business credential. Revoke the existing one first if you really want to re-issue."
      exit 0
    end

    org_name             = ENV.fetch("HOUSTON_ORG_NAME") { abort("Set HOUSTON_ORG_NAME") }
    registration_number  = ENV.fetch("HOUSTON_ORG_REGISTRATION") { abort("Set HOUSTON_ORG_REGISTRATION (e.g. EIN 84-3217605)") }
    jurisdiction         = ENV.fetch("HOUSTON_ORG_JURISDICTION", "US")
    business_type        = ENV.fetch("HOUSTON_ORG_BUSINESS_TYPE", "company")

    subject = {
      type:                "organisation",
      id:                  "org_houston_#{SecureRandom.hex(4)}",
      registration_number: registration_number,
      jurisdiction:        jurisdiction,
    }

    claims = {
      kyb_status:        "pending",
      business_type:     business_type,
      jurisdiction:      jurisdiction,
      registered_name:   org_name,
      tax_id_verified:   false,
    }

    puts "[Beltic] Submitting business credential for #{org_name}…"
    response = Houston::Beltic.issuer.issue_business(subject: subject, claims: claims)

    credential_id = response["credential_id"] || response["id"]
    puts ""
    puts "[Beltic] Business credential issued."
    puts "         credential_id:    #{credential_id}"
    puts "         status:           #{response["status"]}"
    puts "         expires_at:       #{response["expires_at"]}"
    puts ""
    puts "Set this in your environment so future user/agent credentials reference it as parent_business_id:"
    puts ""
    puts "  BELTIC_ORG_CREDENTIAL_ID=#{credential_id}"
    puts ""

    if defined?(VerifiableCredential)
      VerifiableCredential.create!(
        credential_id:   credential_id,
        credential_type: "business",
        subject_type:    "Organization",
        subject_id:      0,
        status:          response["status"] || "active",
        signed_payload:  response["signed_payload"],
        claims:          response["claims"] || claims,
        issued_at:       response["issued_at"],
        expires_at:      response["expires_at"],
        raw_response:    response,
      )
      puts "[Beltic] Persisted to verifiable_credentials table."
    end
  end

  desc "Print Beltic config (api_key redacted) for debugging."
  task config: :environment do
    c = Houston::Beltic.config
    puts "configured?           #{c.configured?}"
    puts "base_url:             #{c.base_url}"
    puts "api_key:              #{c.api_key ? "sk_***#{c.api_key[-4..]}" : "(unset)"}"
    puts "org_credential_id:    #{c.org_credential_id || "(unset)"}"
    puts "webhook_secret:       #{c.webhook_secret ? "***" : "(unset)"}"
    puts "issuer_did:           #{c.issuer_did}"
    puts "jwks_url:             #{c.jwks_url}"
  end
end
