require "openssl"
require "base64"

module Houston
  module Beltic
    # Verifies the HMAC-SHA256 signature on incoming Beltic webhook events.
    # Beltic signs using RFC 7797 detached JWT semantics — the signature header
    # is "<algorithm>.<base64url(signature)>" and the signed payload is the raw
    # request body.
    class WebhookVerifier
      SIGNATURE_HEADER = "X-Beltic-Signature".freeze
      ALGORITHM        = "HS256".freeze

      def initialize(secret)
        raise ConfigurationError, "Beltic webhook_secret is not set" if secret.nil? || secret.empty?
        @secret = secret
      end

      # Returns true if the signature is valid, false otherwise.
      # Use this in a controller before parsing JSON.
      def valid?(raw_body, signature_header)
        return false if signature_header.nil? || signature_header.empty?

        algo, encoded_sig = signature_header.split(".", 2)
        return false unless algo == ALGORITHM && encoded_sig

        expected = OpenSSL::HMAC.digest("SHA256", @secret, raw_body)
        provided = Base64.urlsafe_decode64(encoded_sig)
        secure_compare(expected, provided)
      rescue ArgumentError
        false
      end

      def verify!(raw_body, signature_header)
        return if valid?(raw_body, signature_header)
        raise WebhookSignatureError, "Invalid Beltic webhook signature"
      end

      private

      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize
        l = a.unpack("C#{a.bytesize}")
        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res.zero?
      end
    end
  end
end
