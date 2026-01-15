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

#include "sa_validator.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <crypto/proposal/proposal.h>
#include <crypto/transform.h>
#include <credentials/auth_cfg.h>

typedef struct private_sa_validator_t private_sa_validator_t;

/**
 * Private data of an sa_validator_t object.
 */
struct private_sa_validator_t {

	/**
	 * Public interface
	 */
	sa_validator_t public;

	/**
	 * Reload policy settings
	 */
	reload_policy_t policy;
};

ENUM(sa_validity_names, SA_VALID, SA_CONFIG_MISSING,
	"valid",
	"incompatible IKE proposal",
	"incompatible CHILD proposal",
	"incompatible traffic selectors",
	"incompatible authentication",
	"lifetime changed",
	"DPD changed",
	"config missing",
);

/**
 * Load policy settings from strongswan.conf
 */
static void load_policy(private_sa_validator_t *this)
{
	this->policy.check_proposals = lib->settings->get_bool(lib->settings,
		"%s.plugins.vici.reload.check_proposals", TRUE, lib->ns);
	this->policy.check_traffic_selectors = lib->settings->get_bool(lib->settings,
		"%s.plugins.vici.reload.check_traffic_selectors", TRUE, lib->ns);
	this->policy.check_lifetimes = lib->settings->get_bool(lib->settings,
		"%s.plugins.vici.reload.check_lifetimes", FALSE, lib->ns);
	this->policy.check_dpd = lib->settings->get_bool(lib->settings,
		"%s.plugins.vici.reload.check_dpd", FALSE, lib->ns);
	this->policy.check_auth_class = lib->settings->get_bool(lib->settings,
		"%s.plugins.vici.reload.check_auth_class", FALSE, lib->ns);
	this->policy.max_duration = lib->settings->get_int(lib->settings,
		"%s.plugins.vici.reload.max_duration", 86400, lib->ns);
	this->policy.min_delay = lib->settings->get_int(lib->settings,
		"%s.plugins.vici.reload.min_delay", 10, lib->ns);
	this->policy.max_delay = lib->settings->get_int(lib->settings,
		"%s.plugins.vici.reload.max_delay", 10000, lib->ns);
}

/**
 * Check if negotiated proposal matches any configured proposal.
 * Uses proposal_t->matches() which handles RFC 9370 multiple key exchanges.
 *
 * @param negotiated	the negotiated proposal from the SA
 * @param configured	list of configured proposals
 * @param flags			proposal_selection_flag_t flags (e.g., PROPOSAL_SKIP_KE)
 */
static bool proposal_is_compatible(proposal_t *negotiated,
								   linked_list_t *configured,
								   proposal_selection_flag_t flags)
{
	enumerator_t *enumerator;
	proposal_t *cfg_proposal;
	bool compatible = FALSE;

	enumerator = configured->create_enumerator(configured);
	while (enumerator->enumerate(enumerator, &cfg_proposal))
	{
		/*
		 * Use matches() to check if negotiated is compatible with configured.
		 * This handles all transform types including ADDITIONAL_KEY_EXCHANGE_*
		 * from RFC 9370. The flags parameter allows skipping certain transform
		 * types (e.g., PROPOSAL_SKIP_KE for CHILD_SA where DH was used for PFS).
		 */
		if (negotiated->matches(negotiated, cfg_proposal, flags))
		{
			compatible = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return compatible;
}

/**
 * Check if a specific algorithm is present in any configured proposal.
 */
static bool algorithm_in_proposals(linked_list_t *configured,
								   transform_type_t type,
								   uint16_t alg, uint16_t keysize)
{
	enumerator_t *prop_enum, *alg_enum;
	proposal_t *proposal;
	uint16_t cfg_alg, cfg_keysize;
	bool found = FALSE;

	prop_enum = configured->create_enumerator(configured);
	while (prop_enum->enumerate(prop_enum, &proposal))
	{
		alg_enum = proposal->create_enumerator(proposal, type);
		while (alg_enum->enumerate(alg_enum, &cfg_alg, &cfg_keysize))
		{
			if (cfg_alg == alg && (keysize == 0 || cfg_keysize == 0 ||
								   keysize == cfg_keysize))
			{
				found = TRUE;
				break;
			}
		}
		alg_enum->destroy(alg_enum);
		if (found)
		{
			break;
		}
	}
	prop_enum->destroy(prop_enum);
	return found;
}

/**
 * Get detailed proposal differences.
 * Returns a newly allocated string listing all mismatches, or NULL if compatible.
 * Caller must free() the returned string.
 */
static char* get_proposal_diff(proposal_t *negotiated, linked_list_t *configured,
							   proposal_selection_flag_t flags)
{
	char *result = NULL;
	char buf[512];
	int pos = 0;
	enumerator_t *alg_enum;
	uint16_t alg, keysize;
	bool skip_ke = (flags & PROPOSAL_SKIP_KE);

	struct {
		transform_type_t type;
		const char *name;
		bool skip;
	} transforms[] = {
		{ ENCRYPTION_ALGORITHM, "encryption", FALSE },
		{ INTEGRITY_ALGORITHM, "integrity", FALSE },
		{ PSEUDO_RANDOM_FUNCTION, "PRF", FALSE },
		{ KEY_EXCHANGE_METHOD, "DH group", skip_ke },
		{ EXTENDED_SEQUENCE_NUMBERS, "ESN", FALSE },
	};

	buf[0] = '\0';

	for (int i = 0; i < countof(transforms); i++)
	{
		if (transforms[i].skip)
		{
			continue;
		}

		alg_enum = negotiated->create_enumerator(negotiated, transforms[i].type);
		while (alg_enum->enumerate(alg_enum, &alg, &keysize))
		{
			if (alg == 0)
			{
				continue;
			}
			if (!algorithm_in_proposals(configured, transforms[i].type,
										alg, keysize))
			{
				if (pos > 0)
				{
					pos += snprintf(buf + pos, sizeof(buf) - pos, ", ");
				}
				if (keysize > 0)
				{
					pos += snprintf(buf + pos, sizeof(buf) - pos,
									"%s %N_%u no longer allowed",
									transforms[i].name,
									transform_get_enum_names(transforms[i].type),
									alg, keysize);
				}
				else
				{
					pos += snprintf(buf + pos, sizeof(buf) - pos,
									"%s %N no longer allowed",
									transforms[i].name,
									transform_get_enum_names(transforms[i].type),
									alg);
				}
			}
		}
		alg_enum->destroy(alg_enum);
	}

	if (pos > 0)
	{
		result = strdup(buf);
	}
	return result;
}

/**
 * Check if installed traffic selector is covered by any configured TS.
 * Returns TRUE if installed_ts is a subset of at least one configured TS.
 */
static bool ts_is_covered(traffic_selector_t *installed_ts, linked_list_t *configured_ts)
{
	enumerator_t *enumerator;
	traffic_selector_t *cfg_ts, *subset;
	bool covered = FALSE;

	enumerator = configured_ts->create_enumerator(configured_ts);
	while (enumerator->enumerate(enumerator, &cfg_ts))
	{
		/*
		 * get_subset() returns the intersection. If the result equals
		 * installed_ts, then installed_ts is fully contained in cfg_ts.
		 */
		subset = installed_ts->get_subset(installed_ts, cfg_ts);
		if (subset)
		{
			/*
			 * Check if the subset equals the installed TS. If so,
			 * the installed TS is fully covered by this configured TS.
			 */
			if (installed_ts->equals(installed_ts, subset))
			{
				covered = TRUE;
			}
			subset->destroy(subset);
			if (covered)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	return covered;
}

/**
 * Validate traffic selectors for a CHILD_SA against configuration.
 */
static bool validate_traffic_selectors(child_sa_t *child_sa, child_cfg_t *child_cfg)
{
	enumerator_t *ts_enum;
	traffic_selector_t *ts;
	linked_list_t *cfg_local_ts, *cfg_remote_ts, *hosts;
	bool valid = TRUE;

	/* Get configured TS without narrowing (empty hosts list) */
	hosts = linked_list_create();
	cfg_local_ts = child_cfg->get_traffic_selectors(child_cfg, TRUE, hosts);
	cfg_remote_ts = child_cfg->get_traffic_selectors(child_cfg, FALSE, hosts);
	hosts->destroy(hosts);

	/* Check local (our) traffic selectors */
	ts_enum = child_sa->create_ts_enumerator(child_sa, TRUE);
	while (ts_enum->enumerate(ts_enum, &ts))
	{
		if (!ts_is_covered(ts, cfg_local_ts))
		{
			DBG2(DBG_CFG, "  local TS %R not covered by new config", ts);
			valid = FALSE;
			break;
		}
	}
	ts_enum->destroy(ts_enum);

	/* Check remote traffic selectors if local was valid */
	if (valid)
	{
		ts_enum = child_sa->create_ts_enumerator(child_sa, FALSE);
		while (ts_enum->enumerate(ts_enum, &ts))
		{
			if (!ts_is_covered(ts, cfg_remote_ts))
			{
				DBG2(DBG_CFG, "  remote TS %R not covered by new config", ts);
				valid = FALSE;
				break;
			}
		}
		ts_enum->destroy(ts_enum);
	}

	cfg_local_ts->destroy_offset(cfg_local_ts,
								 offsetof(traffic_selector_t, destroy));
	cfg_remote_ts->destroy_offset(cfg_remote_ts,
								  offsetof(traffic_selector_t, destroy));

	return valid;
}

METHOD(sa_validator_t, validate_ike_sa, sa_validity_t,
	private_sa_validator_t *this, ike_sa_t *ike_sa,
	peer_cfg_t *peer_cfg, ike_cfg_t *ike_cfg)
{
	proposal_t *negotiated;
	linked_list_t *configured;

	/* Check proposal compatibility if policy requires */
	if (this->policy.check_proposals)
	{
		negotiated = ike_sa->get_proposal(ike_sa);
		if (!negotiated)
		{
			/* No proposal means SA is not fully established */
			DBG2(DBG_CFG, "  IKE_SA has no negotiated proposal");
			return SA_VALID;  /* Don't terminate, let it complete */
		}

		configured = ike_cfg->get_proposals(ike_cfg);
		/*
		 * For IKE_SA, compare all proposal components including DH group.
		 * The DH group is critical for IKE_SA as it determines the key
		 * exchange security level.
		 */
		if (!proposal_is_compatible(negotiated, configured, 0))
		{
			DBG1(DBG_CFG, "  IKE_SA proposal %P not compatible with new config",
				 negotiated);
			configured->destroy_offset(configured,
									   offsetof(proposal_t, destroy));
			return SA_INCOMPATIBLE_IKE_PROPOSAL;
		}
		configured->destroy_offset(configured,
								   offsetof(proposal_t, destroy));
	}

	/*
	 * Note: Lifetime and DPD checks for IKE_SA would require comparing
	 * the negotiated values with the new config. For now, we only check
	 * proposals as lifetime mismatch for IKE_SA is less critical.
	 */

	return SA_VALID;
}

METHOD(sa_validator_t, validate_child_sa, sa_validity_t,
	private_sa_validator_t *this, child_sa_t *child_sa,
	child_cfg_t *child_cfg)
{
	proposal_t *negotiated;
	linked_list_t *configured;

	/* Check proposal compatibility if policy requires */
	if (this->policy.check_proposals)
	{
		negotiated = child_sa->get_proposal(child_sa);
		if (!negotiated)
		{
			/* No proposal means SA is not fully established */
			DBG2(DBG_CFG, "  CHILD_SA has no negotiated proposal");
			return SA_VALID;  /* Don't terminate, let it complete */
		}

		/*
		 * Get configured proposals including DH groups (FALSE = don't strip).
		 * Use PROPOSAL_SKIP_KE flag to skip DH comparison because:
		 * - CHILD_SA via IKE_AUTH: negotiated proposal has no DH
		 * - CHILD_SA via CREATE_CHILD_SA with PFS: has DH in proposal
		 * In both cases, the DH was used only for key derivation and doesn't
		 * affect the installed SA's encryption/integrity algorithms.
		 */
		configured = child_cfg->get_proposals(child_cfg, FALSE);
		if (!proposal_is_compatible(negotiated, configured, PROPOSAL_SKIP_KE))
		{
			DBG1(DBG_CFG, "  CHILD_SA proposal %P not compatible with new config",
				 negotiated);
			configured->destroy_offset(configured,
									   offsetof(proposal_t, destroy));
			return SA_INCOMPATIBLE_CHILD_PROPOSAL;
		}
		configured->destroy_offset(configured,
								   offsetof(proposal_t, destroy));
	}

	/* Check traffic selector compatibility if policy requires */
	if (this->policy.check_traffic_selectors)
	{
		if (!validate_traffic_selectors(child_sa, child_cfg))
		{
			return SA_INCOMPATIBLE_TS;
		}
	}

	/*
	 * Lifetime check: Compare installed SA lifetime with configured lifetime.
	 * This is optional and controlled by check_lifetimes policy.
	 */
	if (this->policy.check_lifetimes)
	{
		lifetime_cfg_t *cfg_lifetime;

		cfg_lifetime = child_cfg->get_lifetime(child_cfg, FALSE);
		if (cfg_lifetime)
		{
			/*
			 * Note: Direct comparison of lifetime is complex because the
			 * installed SA has absolute timestamps while config has relative
			 * values. For now, we log a debug message but don't invalidate.
			 * A more complete implementation would compare the remaining
			 * lifetime against the configured rekey time.
			 */
			DBG2(DBG_CFG, "  lifetime check: configured rekey_time=%us",
				 cfg_lifetime->time.rekey);
		}
	}

	return SA_VALID;
}

METHOD(sa_validator_t, validate_auth, sa_validity_t,
	private_sa_validator_t *this, ike_sa_t *ike_sa, peer_cfg_t *peer_cfg)
{
	enumerator_t *cfg_enum, *sa_enum;
	auth_cfg_t *cfg_auth, *sa_auth;
	auth_class_t cfg_class, sa_class;

	if (!this->policy.check_auth_class)
	{
		return SA_VALID;
	}

	/*
	 * Compare auth_class for each authentication round.
	 * We check if the configured auth_class matches what was used
	 * during SA establishment.
	 */

	/* Get configured remote auth requirements */
	cfg_enum = peer_cfg->create_auth_cfg_enumerator(peer_cfg, FALSE);

	/* Get completed remote auth rounds from IKE_SA */
	sa_enum = ike_sa->create_auth_cfg_enumerator(ike_sa, FALSE);

	while (cfg_enum->enumerate(cfg_enum, &cfg_auth))
	{
		cfg_class = (auth_class_t)(uintptr_t)cfg_auth->get(cfg_auth,
														   AUTH_RULE_AUTH_CLASS);

		/* Get corresponding completed auth round */
		if (!sa_enum->enumerate(sa_enum, &sa_auth))
		{
			/*
			 * Fewer completed rounds than required - this shouldn't happen
			 * for an established SA, but if auth was flushed we can't validate
			 */
			DBG2(DBG_CFG, "  auth check: completed auth rounds unavailable");
			break;
		}

		sa_class = (auth_class_t)(uintptr_t)sa_auth->get(sa_auth,
														 AUTH_RULE_AUTH_CLASS);

		/* AUTH_CLASS_ANY means any method is acceptable */
		if (cfg_class != AUTH_CLASS_ANY && cfg_class != sa_class)
		{
			DBG1(DBG_CFG, "  auth class mismatch: SA used %N, config requires %N",
				 auth_class_names, sa_class, auth_class_names, cfg_class);
			cfg_enum->destroy(cfg_enum);
			sa_enum->destroy(sa_enum);
			return SA_INCOMPATIBLE_AUTH;
		}
	}

	cfg_enum->destroy(cfg_enum);
	sa_enum->destroy(sa_enum);

	return SA_VALID;
}

METHOD(sa_validator_t, get_ike_proposal_details, char*,
	private_sa_validator_t *this, ike_sa_t *ike_sa, ike_cfg_t *ike_cfg)
{
	proposal_t *negotiated;
	linked_list_t *configured;
	char *details = NULL;

	negotiated = ike_sa->get_proposal(ike_sa);
	if (!negotiated)
	{
		return NULL;
	}

	configured = ike_cfg->get_proposals(ike_cfg);
	details = get_proposal_diff(negotiated, configured, 0);
	configured->destroy_offset(configured, offsetof(proposal_t, destroy));

	return details;
}

METHOD(sa_validator_t, get_child_proposal_details, char*,
	private_sa_validator_t *this, child_sa_t *child_sa, child_cfg_t *child_cfg)
{
	proposal_t *negotiated;
	linked_list_t *configured;
	char *details = NULL;

	negotiated = child_sa->get_proposal(child_sa);
	if (!negotiated)
	{
		return NULL;
	}

	configured = child_cfg->get_proposals(child_cfg, FALSE);
	details = get_proposal_diff(negotiated, configured, PROPOSAL_SKIP_KE);
	configured->destroy_offset(configured, offsetof(proposal_t, destroy));

	return details;
}

METHOD(sa_validator_t, get_policy, reload_policy_t*,
	private_sa_validator_t *this)
{
	return &this->policy;
}

METHOD(sa_validator_t, reload_policy, void,
	private_sa_validator_t *this)
{
	load_policy(this);
	DBG2(DBG_CFG, "reloaded SA validator policy: proposals=%s, ts=%s, "
		 "lifetimes=%s, dpd=%s, auth_class=%s, max_duration=%us",
		 this->policy.check_proposals ? "yes" : "no",
		 this->policy.check_traffic_selectors ? "yes" : "no",
		 this->policy.check_lifetimes ? "yes" : "no",
		 this->policy.check_dpd ? "yes" : "no",
		 this->policy.check_auth_class ? "yes" : "no",
		 this->policy.max_duration);
}

METHOD(sa_validator_t, destroy, void,
	private_sa_validator_t *this)
{
	free(this);
}

/*
 * Described in header
 */
sa_validator_t *sa_validator_create(void)
{
	private_sa_validator_t *this;

	INIT(this,
		.public = {
			.validate_ike_sa = _validate_ike_sa,
			.validate_child_sa = _validate_child_sa,
			.validate_auth = _validate_auth,
			.get_ike_proposal_details = _get_ike_proposal_details,
			.get_child_proposal_details = _get_child_proposal_details,
			.get_policy = _get_policy,
			.reload_policy = _reload_policy,
			.destroy = _destroy,
		},
	);

	load_policy(this);

	DBG2(DBG_CFG, "SA validator initialized: proposals=%s, ts=%s, "
		 "lifetimes=%s, dpd=%s, auth_class=%s",
		 this->policy.check_proposals ? "yes" : "no",
		 this->policy.check_traffic_selectors ? "yes" : "no",
		 this->policy.check_lifetimes ? "yes" : "no",
		 this->policy.check_dpd ? "yes" : "no",
		 this->policy.check_auth_class ? "yes" : "no");

	return &this->public;
}
