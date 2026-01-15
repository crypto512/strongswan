/*
 * Copyright (C) 2026 crypto512
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup sa_validator sa_validator
 * @{ @ingroup config
 */

#ifndef SA_VALIDATOR_H_
#define SA_VALIDATOR_H_

typedef enum sa_validity_t sa_validity_t;
typedef struct sa_validator_t sa_validator_t;
typedef struct reload_policy_t reload_policy_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/child_sa.h>
#include <config/peer_cfg.h>
#include <config/child_cfg.h>
#include <config/ike_cfg.h>

/**
 * Result of SA validation against configuration.
 */
enum sa_validity_t {
	/** SA is compatible with configuration */
	SA_VALID,
	/** IKE SA proposal is incompatible with configuration */
	SA_INCOMPATIBLE_IKE_PROPOSAL,
	/** CHILD SA proposal is incompatible with configuration */
	SA_INCOMPATIBLE_CHILD_PROPOSAL,
	/** Traffic selectors are incompatible with configuration */
	SA_INCOMPATIBLE_TS,
	/** Authentication configuration changed */
	SA_INCOMPATIBLE_AUTH,
	/** Lifetime configuration changed (if policy requires restart) */
	SA_LIFETIME_CHANGED,
	/** DPD configuration changed (if policy requires restart) */
	SA_DPD_CHANGED,
	/** Configuration for this SA no longer exists */
	SA_CONFIG_MISSING,
};

/**
 * enum names for sa_validity_t
 */
extern enum_name_t *sa_validity_names;

/**
 * Policy settings for configuration reload behavior.
 * Read from strongswan.conf: charon.plugins.vici.reload.*
 */
struct reload_policy_t {
	/** Check and restart on proposal mismatch (default: TRUE) */
	bool check_proposals;
	/** Check and restart on traffic selector change (default: TRUE) */
	bool check_traffic_selectors;
	/** Check and restart on lifetime change (default: FALSE) */
	bool check_lifetimes;
	/** Check and restart on DPD change (default: FALSE) */
	bool check_dpd;
	/** Check and restart on auth type change (default: FALSE) */
	bool check_auth_class;
	/** Maximum duration for all terminations in seconds (default: 86400) */
	uint32_t max_duration;
	/** Minimum delay between terminations in ms (default: 10) */
	uint32_t min_delay;
	/** Maximum delay between terminations in ms (default: 10000) */
	uint32_t max_delay;
};

/**
 * SA validator validates running SAs against new configuration.
 *
 * This module determines if running IKE_SAs and CHILD_SAs are compatible
 * with a new configuration. It compares negotiated parameters against
 * the new configuration and returns whether the SA needs to be terminated.
 *
 * The validation respects configurable policies that determine which
 * parameter changes require SA restart.
 */
struct sa_validator_t {

	/**
	 * Validate an IKE_SA against a new configuration.
	 *
	 * Checks if the running IKE_SA's negotiated parameters are compatible
	 * with the new peer and IKE configuration. This includes:
	 * - IKE proposal (encryption, integrity, PRF, KE methods including RFC 9370)
	 * - Authentication if policy requires
	 * - Lifetime if policy requires
	 * - DPD if policy requires
	 *
	 * @param ike_sa		running IKE_SA to validate
	 * @param peer_cfg		new peer configuration
	 * @param ike_cfg		new IKE configuration
	 * @return				validation result
	 */
	sa_validity_t (*validate_ike_sa)(sa_validator_t *this,
									 ike_sa_t *ike_sa,
									 peer_cfg_t *peer_cfg,
									 ike_cfg_t *ike_cfg);

	/**
	 * Validate a CHILD_SA against a new child configuration.
	 *
	 * Checks if the running CHILD_SA's negotiated parameters are compatible
	 * with the new child configuration. This includes:
	 * - ESP/AH proposal (encryption, integrity, KE methods for PFS including RFC 9370)
	 * - Traffic selectors (installed TS must be subset of configured TS)
	 * - Lifetime if policy requires
	 *
	 * @param child_sa		running CHILD_SA to validate
	 * @param child_cfg		new child configuration
	 * @return				validation result
	 */
	sa_validity_t (*validate_child_sa)(sa_validator_t *this,
									   child_sa_t *child_sa,
									   child_cfg_t *child_cfg);

	/**
	 * Validate IKE_SA authentication against new configuration.
	 *
	 * Checks if the completed authentication rounds are compatible with
	 * the new peer configuration. Currently only checks auth_class
	 * (PUBKEY, PSK, EAP, XAUTH) if check_auth_class policy is enabled.
	 *
	 * Note: This is a simple check that only validates the authentication
	 * method type, not the specific credentials used. Full credential
	 * validation (certificate comparison, PSK identity) may be added later.
	 *
	 * @param ike_sa		running IKE_SA to validate
	 * @param peer_cfg		new peer configuration
	 * @return				validation result
	 */
	sa_validity_t (*validate_auth)(sa_validator_t *this,
								   ike_sa_t *ike_sa,
								   peer_cfg_t *peer_cfg);

	/**
	 * Get detailed proposal incompatibility description.
	 *
	 * Returns a string describing exactly which algorithms in the negotiated
	 * proposal are not present in any configured proposal. Lists all
	 * mismatches (encryption, integrity, PRF, DH group, ESN).
	 *
	 * @param ike_sa		IKE_SA to get negotiated proposal from
	 * @param ike_cfg		IKE configuration to compare against
	 * @return				newly allocated string, or NULL if compatible
	 *						(caller must free)
	 */
	char* (*get_ike_proposal_details)(sa_validator_t *this,
									  ike_sa_t *ike_sa,
									  ike_cfg_t *ike_cfg);

	/**
	 * Get detailed CHILD proposal incompatibility description.
	 *
	 * @param child_sa		CHILD_SA to get negotiated proposal from
	 * @param child_cfg		child configuration to compare against
	 * @return				newly allocated string, or NULL if compatible
	 *						(caller must free)
	 */
	char* (*get_child_proposal_details)(sa_validator_t *this,
										child_sa_t *child_sa,
										child_cfg_t *child_cfg);

	/**
	 * Get the reload policy settings.
	 *
	 * @return				current reload policy (internal reference)
	 */
	reload_policy_t* (*get_policy)(sa_validator_t *this);

	/**
	 * Reload policy settings from configuration.
	 *
	 * Re-reads the policy settings from strongswan.conf. Call this
	 * after reload-settings to pick up any policy changes.
	 */
	void (*reload_policy)(sa_validator_t *this);

	/**
	 * Destroy a sa_validator_t instance.
	 */
	void (*destroy)(sa_validator_t *this);
};

/**
 * Create a SA validator instance.
 *
 * Reads policy settings from strongswan.conf:
 *   charon.plugins.vici.reload.check_proposals = yes
 *   charon.plugins.vici.reload.check_traffic_selectors = yes
 *   charon.plugins.vici.reload.check_lifetimes = no
 *   charon.plugins.vici.reload.check_dpd = no
 *   charon.plugins.vici.reload.check_auth_class = no
 *   charon.plugins.vici.reload.max_duration = 86400
 *   charon.plugins.vici.reload.min_delay = 10
 *   charon.plugins.vici.reload.max_delay = 10000
 *
 * @return					sa_validator_t instance
 */
sa_validator_t *sa_validator_create(void);

#endif /** SA_VALIDATOR_H_ @}*/
