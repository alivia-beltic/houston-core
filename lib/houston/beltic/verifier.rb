module Houston
  module Beltic
    # Verifies a Beltic-issued JWT-VC. Two paths:
    #
    #   - Local (`verify`): sub-ms, no network at transaction time. Uses cached JWKS
    #     and the Status List 2021 bitstring. Use this in the hot purchase path.
    #
    #   - Server-side (`verify_remote!`): calls POST /v1/credentials/:id/verify on
    #     Beltic, producing an audit-trail event. Use this for compliance-sensitive
    #     operations or when you want every verification logged centrally.
    #
    # NOTE: this is a stub. Full local verification requires the JWKS cache, the
    # status list bitstring fetcher, JWT signature verification, and the
    # permission-policy evaluator. Each is its own file; ticket out as Phase 3.
    class Verifier
      attr_reader :config

      def initialize(config)
        @config = config
      end

      # Local verification. ctx contains the transaction details to evaluate
      # against the credential's permission conditions (e.g.,
      # { resource_type: "wallet", action: "checkout",
      #   transaction_amount: 5000, transaction_currency: "USD" }).
      def verify(_jwt, _ctx = {})
        raise NotImplementedError, "Local verifier not yet implemented — see Phase 3"
      end

      # Server-side verification with audit trail.
      def verify_remote!(credential_id, ctx = {})
        Houston::Beltic.client.post("/credentials/#{credential_id}/verify", ctx)
      end

      # Invalidate cached JWKS (call after a key-id miss).
      def invalidate_jwks!
        @jwks_cache = nil
      end
    end
  end
end
