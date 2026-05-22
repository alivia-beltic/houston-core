module Webhooks
  class BelticController < ActionController::Base
    # Beltic webhook receiver. Verifies HMAC, updates the relevant VC row,
    # fires a Houston observer event for downstream subscribers.
    #
    # Events handled: credential.issued | credential.revoked | credential.suspended
    skip_forgery_protection

    def create
      verifier = Houston::Beltic::WebhookVerifier.new(Houston::Beltic.config.webhook_secret)
      verifier.verify!(request.raw_post, request.headers["X-Beltic-Signature"])

      event = JSON.parse(request.raw_post)
      apply_event(event)

      head :ok
    rescue Houston::Beltic::WebhookSignatureError
      head :unauthorized
    rescue JSON::ParserError
      head :bad_request
    end

    private

    def apply_event(event)
      credential_id = event.dig("data", "credential_id")
      return unless credential_id

      vc = VerifiableCredential.find_by(credential_id: credential_id)
      return unless vc

      case event["type"]
      when "credential.revoked"
        vc.update!(status: "revoked", revoked_at: Time.current)
      when "credential.suspended"
        vc.update!(status: "suspended")
      when "credential.issued"
        vc.update!(status: "active")
      end

      Houston.observer.fire("beltic.credential_status_changed",
                            credential: vc,
                            event_type: event["type"])
    end
  end
end
