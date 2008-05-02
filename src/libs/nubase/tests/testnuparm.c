#include <stdio.h>
#include <nubase.h>

int main(void)
{
	parse_configuration("../../../../conf/nuauth.conf");

	printf("nuauth_client_listen_addr=%s\n", nubase_config_table_get_alwaysstring("nuauth_client_listen_addr"));
	printf("nuauth_nufw_listen_addr=%s\n", nubase_config_table_get_alwaysstring("nuauth_nufw_listen_addr"));
	printf("nufw_gw_addr=%s\n", nubase_config_table_get_alwaysstring("nufw_gw_addr"));
	printf("nuauth_gw_packet_port=%s\n", nubase_config_table_get_alwaysstring("nuauth_gw_packet_port"));
	printf("nuauth_user_packet_port=%s\n", nubase_config_table_get_alwaysstring("nuauth_user_packet_port"));
	printf("nuauth_number_usercheckers=%s\n", nubase_config_table_get_alwaysstring("nuauth_number_usercheckers"));
	printf("nuauth_number_aclcheckers=%s\n", nubase_config_table_get_alwaysstring("nuauth_number_aclcheckers"));
	printf("nuauth_number_ipauthcheckers=%s\n", nubase_config_table_get_alwaysstring("nuauth_number_ipauthcheckers"));
	printf("nuauth_log_users=%s\n", nubase_config_table_get_alwaysstring("nuauth_log_users"));
	printf("nuauth_log_users_sync=%s\n", nubase_config_table_get_alwaysstring("nuauth_log_users_sync"));
	printf("nuauth_log_users_strict=%s\n", nubase_config_table_get_alwaysstring("nuauth_log_users_strict"));
	printf("nuauth_log_users_without_realm=%s\n", nubase_config_table_get_alwaysstring("nuauth_log_users_without_realm"));
	printf("nuauth_prio_to_nok=%s\n", nubase_config_table_get_alwaysstring("nuauth_prio_to_nok"));
	printf("nuauth_single_user_client_limit=%s\n", nubase_config_table_get_alwaysstring("nuauth_single_user_client_limit"));
	printf("nuauth_single_ip_client_limit=%s\n", nubase_config_table_get_alwaysstring("nuauth_single_ip_client_limit"));
	printf("nuauth_connect_policy=%s\n", nubase_config_table_get_alwaysstring("nuauth_connect_policy"));
	printf("nuauth_reject_after_timeout=%s\n", nubase_config_table_get_alwaysstring("nuauth_reject_after_timeout"));
	printf("nuauth_reject_authenticated_drop=%s\n", nubase_config_table_get_alwaysstring("nuauth_reject_authenticated_drop"));
	printf("nuauth_number_loggers=%s\n", nubase_config_table_get_alwaysstring("nuauth_number_loggers"));
	printf("nuauth_number_session_loggers=%s\n", nubase_config_table_get_alwaysstring("nuauth_number_session_loggers"));
	printf("nuauth_number_authcheckers=%s\n", nubase_config_table_get_alwaysstring("nuauth_number_authcheckers"));
	printf("nuauth_packet_timeout=%s\n", nubase_config_table_get_alwaysstring("nuauth_packet_timeout"));
	printf("nuauth_session_duration=%s\n", nubase_config_table_get_alwaysstring("nuauth_session_duration"));
	printf("nuauth_datas_persistance=%s\n", nubase_config_table_get_alwaysstring("nuauth_datas_persistance"));
	printf("nuauth_push_to_client=%s\n", nubase_config_table_get_alwaysstring("nuauth_push_to_client"));
	printf("nuauth_do_ip_authentication=%s\n", nubase_config_table_get_alwaysstring("nuauth_do_ip_authentication"));
	printf("nuauth_acl_cache=%s\n", nubase_config_table_get_alwaysstring("nuauth_acl_cache"));
	printf("nuauth_user_cache=%s\n", nubase_config_table_get_alwaysstring("nuauth_user_cache"));
	printf("nuauth_uses_utf8=%s\n", nubase_config_table_get_alwaysstring("nuauth_uses_utf8"));
	printf("nuauth_hello_authentication=%s\n", nubase_config_table_get_alwaysstring("nuauth_hello_authentication"));
	printf("nuauth_debug_areas=%s\n", nubase_config_table_get_alwaysstring("nuauth_debug_areas"));
	printf("nuauth_debug_level=%s\n", nubase_config_table_get_alwaysstring("nuauth_debug_level"));
	printf("nufw_has_conntrack=%s\n", nubase_config_table_get_alwaysstring("nufw_has_conntrack"));
	printf("nufw_has_fixed_timeout=%s\n", nubase_config_table_get_alwaysstring("nufw_has_fixed_timeout"));
	printf("nuauth_uses_fake_sasl=%s\n", nubase_config_table_get_alwaysstring("nuauth_uses_fake_sasl"));
	printf("nuauth_use_command_server=%s\n", nubase_config_table_get_alwaysstring("nuauth_use_command_server"));
	printf("nuauth_proto_wait_delay=%s\n", nubase_config_table_get_alwaysstring("nuauth_proto_wait_delay"));
	printf("nuauth_drop_if_no_logging=%s\n", nubase_config_table_get_alwaysstring("nuauth_drop_if_no_logging"));
	printf("nuauth_max_unassigned_messages=%s\n", nubase_config_table_get_alwaysstring("nuauth_max_unassigned_messages"));
	printf("nuauth_push_delay=%s\n", nubase_config_table_get_alwaysstring("nuauth_push_delay"));

	return 0;
}

