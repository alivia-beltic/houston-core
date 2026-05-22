module Beltic
  # Async wrapper around Houston::Beltic::Issuer. Retries with backoff on
  # transport/server errors. Does NOT retry on schema or attestation errors —
  # those are programmer/user errors that won't fix themselves.
  class IssueCredentialJob < ActiveJob::Base
    queue_as :default

    retry_on Houston::Beltic::TransportError, wait: :exponentially_longer, attempts: 5
    retry_on Houston::Beltic::ServerError,    wait: :exponentially_longer, attempts: 5
    discard_on Houston::Beltic::SelfAttestationIncompleteError
    discard_on Houston::Beltic::SchemaValidationError
    discard_on Houston::Beltic::DelegationMissingError

    def perform(kind:, user_id: nil, agent_id: nil, claims: nil)
      case kind.to_sym
      when :user                  then issue_user(user_id, claims)
      when :agent_authorization   then issue_agent_authorization(agent_id)
      else
        raise ArgumentError, "Unknown credential kind: #{kind.inspect}"
      end
    end

    private

    def issue_user(user_id, claims)
      user = User.find(user_id)
      subject = {
        type:       "person",
        id:         "usr_#{user.id}",
        email:      user.email,
        first_name: user.first_name,
        last_name:  user.last_name,
      }
      response = Houston::Beltic.issuer.issue_user(subject: subject, claims: claims)
      persist!(response, subject_type: "User", subject_id: user.id)
    end

    def issue_agent_authorization(agent_id)
      agent = Agent.find(agent_id)
      user_cred = agent.user.beltic_user_credential
      raise "User #{agent.user.id} has no active Beltic credential" unless user_cred&.active?

      subject = {
        type:                 "agent",
        id:                   agent.did,
        agent_external_id:    "agent_#{agent.id}",
        parent_user_id:       user_cred.credential_id,
        parent_business_id:   Houston::Beltic.config.org_credential_id,
      }
      claims = build_agent_claims(agent, user_cred)
      response = Houston::Beltic.issuer.issue_agent_authorization(subject: subject, claims: claims)
      persist!(response, subject_type: "Agent", subject_id: agent.id,
                         delegated_by_credential_id: user_cred.id)
    end

    def build_agent_claims(agent, user_cred)
      {
        permissions: [{
          resource_type: "wallet",
          resource_id:   "*",
          actions:       %w[checkout payment_authorize],
          conditions: [
            { operator: "lte", field: "transaction_amount", value: agent.per_transaction_max_cents }
          ],
        }],
        delegated_by_subject_id: user_cred.credential_id,
        spend_limit: {
          amount:   agent.spend_limit_amount_cents,
          currency: agent.spend_limit_currency,
          period:   agent.spend_limit_period,
        },
        authorized_currencies: agent.authorized_currencies,
        max_idle_duration:     agent.max_idle_duration_iso8601,
        human_present:         agent.confirmation_mode != "never",
      }
    end

    def persist!(response, subject_type:, subject_id:, delegated_by_credential_id: nil)
      VerifiableCredential.create!(
        credential_id:               response["credential_id"] || response["id"],
        credential_type:             response["credential_type"],
        subject_type:                subject_type,
        subject_id:                  subject_id,
        status:                      response["status"] || "active",
        signed_payload:              response["signed_payload"],
        claims:                      response["claims"] || {},
        evidence_refs:               response["evidence_refs"] || [],
        delegated_by_credential_id:  delegated_by_credential_id,
        issued_at:                   response["issued_at"],
        expires_at:                  response["expires_at"],
        raw_response:                response,
      )
    end
  end
end
