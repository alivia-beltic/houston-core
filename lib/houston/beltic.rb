require "houston/beltic/errors"
require "houston/beltic/client"
require "houston/beltic/issuer"
require "houston/beltic/verifier"
require "houston/beltic/webhook_verifier"

module Houston
  module Beltic
    class Configuration
      attr_accessor :api_key, :base_url, :webhook_secret, :org_credential_id,
                    :issuer_did, :jwks_url, :status_list_url,
                    :request_timeout, :open_timeout

      def initialize
        @base_url        = "https://api.beltic.com/v1"
        @issuer_did      = "did:web:beltic.com"
        @jwks_url        = "https://api.beltic.com/.well-known/jwks.json"
        @status_list_url = "https://api.beltic.com/.well-known/status-lists/v1"
        @request_timeout = 10
        @open_timeout    = 5
      end

      def configured?
        !api_key.nil? && !api_key.empty?
      end
    end

    class << self
      def config
        @config ||= Configuration.new
      end

      def configure
        yield(config)
      end

      def client
        @client ||= Client.new(config)
      end

      def issuer
        @issuer ||= Issuer.new(client)
      end

      def verifier
        @verifier ||= Verifier.new(config)
      end

      def reset!
        @client = @issuer = @verifier = nil
      end
    end
  end
end
