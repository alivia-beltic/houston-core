class IdentityVerificationsController < ApplicationController
  before_action :authenticate_user!

  # GET /identity_verification/new
  # Renders the self-attestation modal (Figma: "Verify Your Identity").
  def new
    @existing = current_user.beltic_user_credential
  end

  # POST /identity_verification
  # Creates a pending VC row and enqueues an async issuance job.
  # Beltic enforces `self_attestation_complete: true` server-side; we only
  # set it to true after the user has actually checked the consent boxes.
  def create
    unless attestation_complete?
      flash[:error] = "Please confirm all declarations before submitting."
      render :new, status: :unprocessable_entity and return
    end

    Beltic::IssueCredentialJob.perform_later(
      kind:    :user,
      user_id: current_user.id,
      claims:  user_claims_from_params,
    )

    redirect_to settings_identity_path,
                notice: "Submitted — Beltic is issuing your credential. You'll see it here in a moment."
  end

  private

  def attestation_complete?
    %w[confirm_accuracy consent_issuance understand_revocation].all? do |key|
      ActiveModel::Type::Boolean.new.cast(params.dig(:declarations, key))
    end
  end

  def user_claims_from_params
    {
      kyc_status:           "approved",
      trust_level:          determine_trust_level,
      nationality:          params[:nationality],
      date_of_birth:        params[:date_of_birth],
      id_document_type:     params[:id_document_type].presence,
      id_document_country:  params[:id_document_country].presence,
      parent_business_id:   Houston::Beltic.config.org_credential_id,
    }.compact
  end

  def determine_trust_level
    params[:id_document_type].present? ? "idv_verified" : "self_attested"
  end
end
