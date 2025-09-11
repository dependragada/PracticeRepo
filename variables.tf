variable "aws_region" {
  type    = string
}

#Below region is for small naming covention only and value it abstaction of aws_region variable(e.g us-east-2 --->ue2)
variable "region" {
  type    = string
}
variable "environment" {
  type    = string
}
variable "organization" {
  type    = string
}

#####################################  VPC-Variables & Values  ##################################### 
variable "subnet_1" {
  type    = string
}
variable "subnet_2" {
  type    = string
}
variable "subnet_3" {
  type    = string
}

variable "existing_nat_gateway" {
  type    = bool
}
variable "existing_nat_gateway_allocation_id" {
  type    = bool
}
variable "nat_gateway_allocation_id" {
  type        = string
  description = "ID of the existing NAT gateway allocation"
}
variable "nat_gateway_id" {
  type        = string
  description = "ID of the existing NAT gateway"
}
###############################  open-search-variables ######################################
variable "opensearch_engine" {
  type    = string
}
variable "opensearch_instance_type" {
  type    = string
}
############################### CloudMap Variables ######################################
variable "private_dns_namespace" {
  description = "The private dns namespace for the environment"
  type        = string
}
variable "opensearch_service_discovery_instance_id" {
  type    = string
}

################################  Load-Balancer  ###############################
variable "load_balancer_type" {
  type    = string
}

variable "is_load_balancer_internal" {
  type    = bool
}

############################ ECS-Service-Common-variables #######################
# ECS-service port
variable "ecs_service_port" {
  type    = string
}

variable "datasource_driver_class_name" {
  type    = string
}

variable "app_context_id" {
  type    = string
}

variable "ecs_server_ssl_enabled" {
  type    = string
}

variable "elasticache_redis_ssl_enabled" {
  type    = string
}

variable "elasticache_redis_database" {
  type    = string
}
variable "elasticache_redis_use_key_prefix" {
  type    = string
}

variable "elasticache_redis_repositories_enabled" {
  type    = string
}

variable "spring_autoconfigure_exclude" {
  type    = string
}


variable "naix_services_tesseract_path" {
  type    = string
}

variable "naix_services_poppler_path" {
  type    = string
}

variable "login_credentials" {
  type    = string
}

variable "submit_temp_folder_path" {
  type        = string
}

variable "upload_temp_folder_path" {
  type        = string
}

variable "textract_region_name" {
  type = string
}

variable "output_log_folder" {
  type    = string
}

#1.Java Services API URI
variable "document_repo_api_uri" {
  type    = string
}

variable "scan_on_demand_api_uri" {
  type    = string
}

variable "metadata_schema_api_uri" {
  type    = string
}

variable "document_metadata_submission_api_uri" {
  type    = string
}

variable "security_api_uri" {
  type    = string
}

variable "s3_api_uri" {
  type    = string
}

variable "metadata_search_api_uri" {
  type    = string
}

variable "records_management_api_uri" {
  type    = string
}

variable "external_service_api_uri" {
  type    = string
}
variable "transform_api_uri" {
  type    = string
}

variable "buow_api_uri" {
  type    = string
}
variable "rules_api_uri" {
  type    = string
}

variable "alfresco_api_uri" {
  type    = string
}

#2.NAIX service api uri
variable "ailet_gateway_api_uri" {
  type    = string
}

variable "gri_extraction_api_uri" {
  type    = string
}

variable "batch_driver_api_uri" {
  type    = string
}

variable "naix_object_classification_api_uri" {
  type    = string
}

variable "object_driver_api_uri" {
  type    = string
}

variable "output_driver_api_uri" {
  type    = string
}

variable "run_ocr_api_uri" {
  type    = string
}

variable "xml_service_api_uri" {
  type    = string
}

variable "tege_packager_api_uri" {
  type    = string
}

########################### ECS Variable #######################################

#variable for the front-end management console
variable "react_app_cpu_unit" {
  type    = string
}

variable "react_app_memory_unit" {
  type    = string

}
variable "react_app_eauth_logout_url" {
  description = "URL for logging out from EAuth"
  type        = string
}

variable "react_app_time_out" {
  description = "Timeout value for the React App"
  type        = string
}

variable "react_app_eauth_disable" {
  description = "Whether EAuth is disabled in the React App"
  type        = string
}

variable "react_app_okta_base_url" {
  description = "Base URL for Okta in the React App"
  type        = string
}

variable "react_app_okta_client_id" {
  description = "Client ID for Okta in the React App"
  type        = string
}

variable "react_app_s3_user_guide_folder_name" {
  description = "S3 Folder Name for User Guide"
  type        = string
}

variable "react_app_user_guide_object_name" {
  description = "S3 Object Name for the User Guide"
  type        = string
}

variable "react_app_client_name" {
  description = "Client Name for the React App"
  type        = string
}

variable "react_app_guide_visible" {
  description = "Whether the User Guide is visible in the React App"
  type        = string
}


# Variables for the buow api
variable "buow_api_cpu_unit" {
  type    = string
}
variable "buow_api_memory_unit" {
  type    = string
}

variable "buow_api_retry_maxattempts" {
  description = "Maximum retry attempts for the BUOW API"
  type        = string
}

variable "buow_api_retry_timeinterval" {
  description = "Retry time interval for the BUOW API"
  type        = string
}

variable "buow_api_sentiment_api_service_uri" {
  description = "URI for the Sentiment Analysis API service"
  type        = string
}

variable "buow_api_readability_api_service_uri" {
  description = "URI for the Readability API service"
  type        = string
}

variable "buow_api_summary_api_service_uri" {
  description = "URI for the Summary API service"
  type        = string
}

variable "buow_api_language_api_service_uri" {
  description = "URI for the Language Detection API service"
  type        = string
}

variable "buow_api_truth_api_service_uri" {
  description = "URI for the Truth API service"
  type        = string
}

variable "buow_api_spring_flyway_out_of_order" {
  description = "Whether Spring Flyway is out of order"
  type        = string
}

# variables for records management api service
variable "rdms_cpu_unit" {
  type    = string
}

variable "rdms_memory_unit" {
  type    = string
}

variable "rdms_amazonproperties_awsrbatchjob_execution_param" {
  description = "The AWS batch job execution parameter"
  type        = string
}

variable "rdms_retry_maxattempts" {
  description = "Maximum number of retry attempts"
  type        = string
}

variable "rdms_retry_timeinterval" {
  description = "The time interval between retry attempts"
  type        = string
}

# varibales for the document and metadata submission api
variable "doc_metadata_sub_cpu_unit" {
  type        = string
  description = "CPU unit for Document Metatdata Submisstion api service"
}

variable "doc_metadata_sub_memory_unit" {
  type        = string
  description = "Memory unit for Document Metatdata Submisstion api service"
}

variable "doc_metadata_sub_spring_servlet_multipart_max_file_size" {
  type    = string
}

variable "doc_metadata_sub_spring_servlet_multipart_max_request_size" {
  type    = string
}

variable "doc_metadata_sub_retry_maxattempts" {
  type    = string
}

variable "doc_metadata_sub_retry_timeinterval" {
  type    = string
}

# variable for the External service api
variable "external_service_cpu_unit" {
  type    = string
}

variable "external_service_memory_unit" {
  type    = string
}

variable "external_service_datasource" {
  type    = string
}

variable "external_service_scims_uri" {
  type    = string
}

variable "external_service_lsd_uri" {
  type    = string
}

variable "external_service_eas_uri" {
  type    = string
}

variable "external_service_zroles_service_uri" {
  type    = string
}

variable "external_service_zroles_service_getuseraccessrolesandscopes_soap_action" {
  type    = string
}

variable "external_service_zroles_service_namespace_uri" {
  type    = string
}

variable "external_service_zroles_service_ws_secured_token" {
  type    = string
}

variable "external_service_eas_testeauthid" {
  type    = string
}

variable "external_service_eas_testrole" {
  type    = string
}

#variables for the document repository api
variable "doc_repo_cpu_unit" {
  type    = string
}
variable "doc_repo_memory_unit" {
  type    = string
}

variable "doc_repo_spring_servlet_multipart_max_file_size" {
  type    = string
}

variable "doc_repo_spring_servlet_multipart_max_request_size" {
  type    = string
}

variable "doc_repo_retry_maxattempts" {
  type    = string
}

variable "doc_repo_retry_timeinterval" {
  type    = string
}

#variables for the rule api service
variable "rule_api_cpu_unit" {
  type    = string
}
variable "rule_api_memory_unit" {
  type    = string
}


#variables for the metadata schema api
variable "metadata_schema_cpu_unit" {
  type    = string
}
variable "metadata_schema_memory_unit" {
  type    = string
}

#variables for the metadata search api
variable "metadata_search_cpu_unit" {
  type    = string
}
variable "metadata_search_memory_unit" {
  type    = string
}

variable "metadata_search_elasticsearch_port" {
  type    = string
}

variable "metadata_search_elasticsearch_index_name" {
  type    = string
}

#Variables for the s3-api service
variable "s3_api_cpu_unit" {
  type    = string
}
variable "s3_api_memory_unit" {
  type    = string
}

variable "s3_api_max_file_size" {
  type    = string
}

variable "s3_api_max_request_size" {
  type    = string
}

#variables fot the IRS secruity soi service
variable "irs_security_cpu_unit" {
  type    = string
}
variable "irs_security_memory_unit" {
  type    = string
}

variable "irs_security_retry_maxattempts" {
  type    = string
}
variable "irs_security_retry_timeinterval" {
  type    = string
}

variable "irs_security_okta_issuer" {
  type    = string
}

#variables for the transform api
variable "transform_api_cpu_unit" {
  type    = string
}
variable "transform_api_memory_unit" {
  type    = string
}

variable "transform_api_oracle_wallet_directory" {
  type    = string
}

variable "transform_api_qaqcapi_service_host" {
  type    = string
}

variable "transform_api_qaqcapi_service_port" {
  type    = string
}

variable "transform_api_qaqcapi_service_uri" {
  type    = string
}

variable "transform_api_edw_enabled" {
  type    = string
}

#variable for the Scan-On-Demand-Api service
variable "sod_cpu_unit" {
  type    = string
}
variable "sod_memory_unit" {
  type    = string
}
variable "sod_s3_folder_name" {
  type    = string
}

variable "sod_local_upload_path" {
  type    = string
}

variable "sod_spring_servlet_multipart_max_file_size" {
  type    = string
}

variable "sod_spring_servlet_multipart_max_request_size" {
  type    = string
}

variable "sod_retry_maxattempts" {
  type    = string
}

variable "sod_retry_timeinterval" {
  type    = string
}

////////////////////////////////////////////////////////////////////////////////////////

#variables for the ailet gateway service
variable "ailet_gateway_cpu_unit" {
  type    = string
}
variable "ailet_gateway_memory_unit" {
  type    = string
}

#variables for Gri-Extraction service
variable "gri_extraction_cpu_unit" {
  type    = string
}
variable "gri_extraction_memory_unit" {
  type    = string
}

#variable for the Upload Daemon
variable "upload_daemon_cpu_unit" {
  type    = string
}

variable "upload_daemon_memory_unit" {
  type    = string
}

variable "upload_daemon_daemon" {
  type    = string
}

variable "upload_daemon_workers" {
  type    = string
}

variable "upload_daemon_thread" {
  type    = string
}

variable "upload_daemon_textract_aws_access_key_id" {
  type    = string
}

variable "upload_daemon_textract_aws_secret_access_key" {
  type    = string
}

#variables for the routing daemons
variable "routing_daemon_cpu_unit" {
  type    = string
}

variable "routing_daemon_memory_unit" {
  type    = string
}

#variables for the Inbasket daemon
variable "inbasket_daemon_cpu_unit" {
  type    = string
}

variable "inbasket_daemon_memory_unit" {
  type    = string
}

#variables for the submit daemon service
variable "submit_daemon_cpu_unit" {
  type    = string
}

variable "submit_daemon_memory_unit" {
  type    = string
}

variable "submit_daemon_daemon" {
  type    = string
}


variable "submit_daemon_thread" {
  description = "Number of threads to use"
  type        = string
}

variable "submit_daemon_workers" {
  description = "Number of workers"
  type        = string
}

#variables for the sense daemon
variable "sense_daemon_cpu_unit" {
  type    = string
}

variable "sense_daemon_memory_unit" {
  type    = string
}

#variable for the dashboard daemon service
variable "dashboard_daemon_cpu_unit" {
  type    = string
}

variable "dashboard_daemon_memory_unit" {
  type    = string
}

#variables for the Batch-Driver service
variable "batch_driver_cpu_unit" {
  type    = string
}

variable "batch_driver_memory_unit" {
  type    = string
}

#variables fot the tege packager service
variable "tege_packager_cpu_unit" {
  type    = string
}

variable "tege_packager_memory_unit" {
  type    = string
}

variable "tege_packager_temp_folder" {
  type    = string
}

variable "tege_packager_login_user" {
  type    = string
}

variable "tege_packager_run_frequency_constant" {
  type    = string
}

#variables for the the NAIX-object classification Service
variable "obj_classification_cpu_unit" {
  type    = string
}

variable "obj_classification_memory_unit" {
  type    = string
}

variable "obj_classification_temp_folder" {
  type    = string
}


#variables for the Object-Driver Service
variable "object_driver_cpu_unit" {
  type    = string
}

variable "object_driver_memory_unit" {
  type    = string
}

variable "object_driver_driver_name" {
  type    = string
}

variable "object_driver_driver_objects" {
  type    = string
}

variable "object_driver_driver_host" {
  type    = string
}

variable "object_driver_driver_full_fuzzy_objects" {
  type    = string
}

variable "object_driver_classify_only" {
  type    = string
}

variable "object_driver_drims_rule_trigger_route" {
  type    = string
}

variable "object_driver_drims_ailet_gateway" {
  type    = string
}

variable "object_driver_tesseract_cmd_windows" {
  type    = string
}

variable "object_driver_tesseract_cmd_macos" {
  type    = string
}

variable "object_driver_sharepoint_url" {
  type    = string
}

variable "object_driver_keyword_config_url" {
  type    = string
}

variable "object_driver_sharepoint_un" {
  type    = string
}

variable "object_driver_sharepoint_pw" {
  type    = string
}

variable "object_driver_drims_url" {
  type    = string
}

#variables for the output driver service
variable "output_driver_cpu_unit" {
  type    = string
}

variable "output_driver_memory_unit" {
  type    = string
}

variable "output_driver_driver_name" {
  type    = string
}

variable "output_driver_driver_objects" {
  type    = string
}

variable "output_driver_driver_host" {
  type    = string
}

#variables for the runocr service
variable "runocr_cpu_unit" {
  type    = string
}

variable "runocr_memory_unit" {
  type    = string
}

variable "runocr_tesseract_cmd_windows" {
  type    = string
}
variable "runocr_tesseract_cmd_macos" {
  type    = string
}

variable "runocr_textract_aws_secret_access_key" {
  type    = string
}

variable "runocr_textract_aws_access_key_id" {
  type    = string
}

variable "runocr_driver_name" {
  type    = string
}

variable "runocr_driver_objects" {
  type    = string
}

variable "runocr_driver_full_fuzzy_objects" {
  type    = string
}

variable "runocr_classify_only" {
  type    = string
}

variable "runocr_drims_url" {
  type    = string
}

variable "runocr_drims_rule_trigger_route" {
  type    = string
}

variable "runocr_driver_host" {
  type    = string
}

variable "runocr_drims_aillet_gateway" {
  type    = string
}

variable "runocr_sharepoint_url" {
  type    = string
}

variable "runocr_keyword_config_url" {
  type    = string
}

variable "runocr_sharepoint_un" {
  type    = string
}

variable "runocr_sharepoint_pw" {
  type    = string
}

#varibales for the xml service
variable "xml_cpu_unit" {
  type    = string
}

variable "xml_memory_unit" {
  type    = string
}

variable "xml_xsl_folder" {
  description = "Folder path for XSL stylesheets"
  type        = string
}

variable "xml_xsl_list" {
  description = "Comma-separated list of XSL files"
  type        = string
}

#variables for the batch-inferred-daemon-mode
variable "batch_inferred_daemon_cpu_unit" {
  type    = string
}

variable "batch_inferred_daemon_memory_unit" {
  type    = string
}

variable "batch_inferred_daemon_ip" {
  type    = string
}

variable "batch_inferred_daemon_shared_directory_username" {
  type    = string
}

variable "batch_inferred_daemon_shared_directory_password" {
  type    = string
}

##################################### EC2-Instance #########################################

#variables for the Bastion windows EC2 instance
variable "windows_bastion_ami_id" {
  type    = string
}
variable "windows_bastion_key" {
  type    = string 
}
variable "windows_bastion_instance_type" {
  type    = string
}
variable "existing_windows_bastion_key" {
  type    = bool
}
variable "windows_bastion_volume_size" {
  type    = number
}

#variables for the Bastion Linux Ec2 Instance
variable "linux_bastion_ami_id" {
  type    = string
}
variable "linux_bastion_key" {
  type    = string
}
variable "linux_bastion_instance_type" {
  type    = string
}
variable "existing_linux_bastion_key" {
  type    = bool
}
variable "linux_bastion_volume_size" {
  type    = number
}

#variables for the private Jenkins Ec2 Instance
variable "private_jenkins_ec2_key" {
  type    = string
}
variable "private_jenkins_ec2_ami_id" {
  type    = string
}
variable "private_jenkins_key" {
  type    = string
}
variable "private_jenkins_instance_type" {
  type    = string
}
variable "existing_private_jenkins_key" {
  type    = bool
}
variable "private_jenkins_ec2_volume_size" {
  type    = number
}


########################################  AWS-Batch-Variables ##############################################
#1. variables for the Records Transfer Batch 

variable "records_transfer_retry_max_attempts" {
  type    = string
}

variable "records_transfer_retry_time_interval" {
  type    = string
}

#variables fr the AWS Batch for the Records Management Disposition Service
variable "records_disposition_batch_job_execution_param" {
  type    = string
}

variable "records_disposition_retry_max_attempts" {
  type    = string
}

variable "records_disposition_retry_time_interval" {
  type    = string
}

#variable for the NAIX AWS Batch Job 
variable "existing_naix_batch_key_pair" {
  type    = bool
}

variable "naix_batch_ec2_key_pair" {
  type    = string
}

variable "naix_batch_daemon" {
  type    = string
}

variable "naix_batch_workers" {
  type    = string
}

variable "naix_batch_threads" {
  type    = string
}

variable "naix_batch_textract_aws_secret_access_key" {
  type    = string
}

variable "naix_batch_textract_aws_access_key_id" {
  type    = string
}

#variables for the Submit Daemon Batch Job
variable "existing_submit_daemon_batch_key_pair" {
  type    = bool
}

variable "submit_daemon_batch_ec2_key_pair" {
  type    = string
}

variable "submit_batch_daemon" {
  type    = string
}

variable "submit_batch_login_credentials" {
  type    = string
}

variable "submit_daemon_batch_workers" {
  type    = string
}
######################################### Aurora Database ###############################################
variable "aurora_engine" {
  type    = string
}
variable "aurora_master_username" {
  type    = string
}
variable "aurora_master_password" {
  type    = string
}
variable "aurora_db_name" {
  type    = string
}
variable "aurora_db_instance_class" {
  type    = string
}

variable "aurora_db_port" {
  type    = string
}

################################  Elastic-Cache Redis Variables ####################################
variable "elasticache_redis_engine" {
  type    = string
}
variable "elasticache_redis_engine_version" {
  type    = string
}
variable "elasticache_redis_node_type" {
  type    = string
}
variable "elasticache_redis_parameter_group_name" {
  type    = string
}
variable "elasticache_redis_port" {
  type    = string
}

####################################### AWS-Lambda ####################################################

variable "runocr_tesseract_lambda_tesseract_cmd_path" {
 type = string
}

############################## Secret-Manager variables##################################
# created variable for database user
variable "dbuser" {
  type    = string
}

variable "dbpassword" {
  type    = string
}

variable "dbengine" {
  type    = string
}

variable "dbhost" {
  type    = string
}

variable "dbport" {
  type    = string
}

variable "dbinstanceidentifier" {
  type    = string
}

# create variable for jwt token 
variable "jwtsecreteauth" {
  type    = string
}

variable "jwtsecretinternal" {
  type    = string
}

variable "jwtsecretpublic" {
  type    = string
}

variable "jwtsecretprivate" {
  type    = string
}

variable "jwtsecretcertificate" {
  type    = string
}

locals {
  env_tag                    = "${var.organization}-${var.environment}"
  opensearch_domain_name     = lower("${var.environment}-${var.region}-opensearch")
  availability_zone_subnet_1 = "${var.aws_region}a"
  availability_zone_subnet_2 = "${var.aws_region}b"
  availability_zone_subnet_3 = "${var.aws_region}c"

  #S3-bucket
  s3_bucket_name                       = "${var.organization}-${var.environment}-${var.region}-s3-bucket"
  s3_transfer_stage_bucket_name        = "${var.organization}-${var.environment}-${var.region}-s3-transfer-stage-bucket"
  s3_transfer_api_bucket_name          = "${var.organization}-${var.environment}-${var.region}-s3-transfer-api-bucket"
  s3_general_bucket_name               = "${var.organization}-${var.environment}-${var.region}-s3-general-bucket"
  s3_tege_historical_files_bucket_name = "${var.organization}-${var.environment}-${var.region}-s3-tege-historical-files-bucket"
  s3_tege_files_bucket_name            = "${var.organization}-${var.environment}-${var.region}-s3-tege-files-bucket"
  s3_redacted_files_bucket_name        = "${var.organization}-${var.environment}-${var.region}-s3-redacted-files-bucket"
  s3_tege_upload_bucket_name           = "${var.organization}-${var.environment}-${var.region}-s3-tege-upload-bucket"
  s3_tege_processed_bucket_name        = "${var.organization}-${var.environment}-${var.region}-s3-tege-processed-bucket"

  #frontend service discovery api call  
  management_console_api_call = "${var.environment}-management-console.${var.private_dns_namespace}"

  #Java service discovery api call
  document_api_call                         = "${var.environment}-document-api.${var.private_dns_namespace}"
  buow_api_call                             = "${var.environment}-buow-api.${var.private_dns_namespace}"
  metadata_schema_api_call                  = "${var.environment}-metadata-schema-api.${var.private_dns_namespace}"
  external_service_api_call                 = "${var.environment}-external-service-api.${var.private_dns_namespace}"
  rule_api_call                             = "${var.environment}-rule-api.${var.private_dns_namespace}"
  records_management_api_call               = "${var.environment}-records-management-api.${var.private_dns_namespace}"
  irs_security_api_call                     = "${var.environment}-irs-security-api.${var.private_dns_namespace}"
  transform_api_call                        = "${var.environment}-transform-api.${var.private_dns_namespace}"
  scan_on_demand_api_call                   = "${var.environment}-scan-on-demand-api.${var.private_dns_namespace}"
  opensearch_api_call                       = "${var.organization}-${var.environment}-${var.region}-opensearch.${var.private_dns_namespace}"
  s3_api_call                               = "${var.environment}-s3-api.${var.private_dns_namespace}"
  metadata_search_api_call                  = "${var.environment}-metadata-search-api.${var.private_dns_namespace}"
  document_and_metadata_submission_api_call = "${var.environment}-document-and-metadata-submission-api.${var.private_dns_namespace}"
  alfresco_api_call                         = "${var.environment}-alfresco-api.${var.private_dns_namespace}"

  #naix service discovery api call
  ailet_gateway_api_call              = "${var.environment}-ailet-gateway.${var.private_dns_namespace}"
  naix_driver_api_call                = "${var.environment}-naix-driver.${var.private_dns_namespace}"
  gri_extraction_api_call             = "${var.environment}-gri-extraction.${var.private_dns_namespace}"
  naix_object_classification_api_call = "${var.environment}-naix-object-classification.${var.private_dns_namespace}"
  object_driver_api_call              = "${var.environment}-object-driver.${var.private_dns_namespace}"
  sense_daemon_api_call               = "${var.environment}-sense-daemon.${var.private_dns_namespace}"
  inbasket_daemon_api_call            = "${var.environment}-inbasket-daemon.${var.private_dns_namespace}"
  xml_service_api_call                = "${var.environment}-xml-service.${var.private_dns_namespace}"
  batch_inferred_mode_daemon_api_call = "${var.environment}-batch-inferred-mode-daemon.${var.private_dns_namespace}"
  output_driver_api_call              = "${var.environment}-output-driver.${var.private_dns_namespace}"
  run_ocr_api_call                    = "${var.environment}-run-ocr.${var.private_dns_namespace}"
  tege_packager_api_call              = "${var.environment}-tege-packager.${var.private_dns_namespace}"
  upload_daemon_api_call              = "${var.environment}-upload-daemon.${var.private_dns_namespace}"
  textract_api_call                   = "${var.environment}-textract.${var.private_dns_namespace}"
  routing_daemon_api_call             = "${var.environment}-routing-daemon.${var.private_dns_namespace}"
  batch_driver_api_call               = "${var.environment}-batch-driver.${var.private_dns_namespace}"
  submit_daemon_api_call              = "${var.environment}-submit-daemon.${var.private_dns_namespace}"
  dashboard_daemon_api_call           = "${var.environment}-dashboard-daemon.${var.private_dns_namespace}"

  #Java-Aws-Batch Naming convention
  records_management_xfer_batch_jobqueue      = "${var.organization}-${var.environment}-records-xfer-batch"
  records_management_xfer_batch_jobdefinition = "${var.organization}-${var.environment}-records-xfer-batch-job-definition"

  #NAIX-AWS-Batch Naming convention
  naix_daemon_batch_jobname       = "${var.organization}-${var.environment}-naix-batch-job-definition-ec2"
  naix_daemon_batch_jobqueue      = "${var.organization}-${var.environment}-naix-batch-job-queue-ec2"
  naix_daemon_batch_jobdefinition = "${var.organization}-${var.environment}-naix-batch-job-definition-ec2"

  submit_daemon_batch_jobname       = "${var.organization}-${var.environment}-submit-daemon-batch-job-definition-ec2"
  submit_daemon_batch_jobqueue      = "${var.organization}-${var.environment}-submit-daemon-batch-job-queue-ec2"
  submit_daemon_batch_jobdefinition = "${var.organization}-${var.environment}-submit-daemon-batch-job-definition-ec2"

  #NAIX services log group and log stream
  upload_daemon_log_group_name  = "${var.environment}-upload-daemon-log-group"
  upload_daemon_log_stream_name = "${var.environment}-upload-daemon-logs"

  routing_daemon_log_group_name  = "${var.environment}-routing-daemon-log-group"
  routing_daemon_log_stream_name = "${var.environment}-routing-daemon-logs"

  inbasket_daemon_log_group_name  = "${var.environment}-inbasket-daemon-log-group"
  inbasket_daemon_log_stream_name = "${var.environment}-inbasket-daemon-logs"

  submit_daemon_log_group_name  = "${var.environment}-submit-daemon-log-group"
  submit_daemon_log_stream_name = "${var.environment}-submit-daemon-logs"

  sense_daemon_log_group_name  = "${var.environment}-sense-daemon-log-group"
  sense_daemon_log_stream_name = "${var.environment}-sense-daemon-logs"

  dashboard_daemon_log_group_name  = "${var.environment}-dashboard-daemon-log-group"
  dashboard_daemon_log_stream_name = "${var.environment}-dashboard-daemon-logs"

  batch_driver_log_group_name  = "${var.environment}-batch-driver-log-group"
  batch_driver_log_stream_name = "${var.environment}-batch-driver-logs"

  tege_packager_log_group_name  = "${var.environment}-tege-packager-log-group"
  tege_packager_log_stream_name = "${var.environment}-tege-packager-logs"

  obj_classification_log_group_name  = "${var.environment}-object-classification-log-group"
  obj_classification_log_stream_name = "${var.environment}-object-classifcation-logs"

  object_driver_log_group_name  = "${var.environment}-object-driver-log-group"
  object_driver_log_stream_name = "${var.environment}-object-driver-logs"

  output_driver_log_group_name  = "${var.environment}-output-driver-log-group"
  output_driver_log_stream_name = "${var.environment}-output-driver-logs"

  runocr_log_group_name  = "${var.environment}-naix-runocr-log-group"
  runocr_log_stream_name = "${var.environment}-runocr-logs"

  xml_log_group_name  = "${var.environment}-xml-service-log-group"
  xml_log_stream_name = "${var.environment}-xml-service-logs"

  naix_batch_log_group_name  = "${var.environment}-naix-daemon-batch-log-group"
  naix_batch_log_stream_name = "${var.environment}-naix-daemon-batch-logs"

  submit_batch_log_group_name  = "${var.environment}-submit-daemon-batch-log-group"
  submit_batch_log_stream_name = "${var.environment}-submit-daemon-batch-logs"

  tege_packager_lambda_log_group_name  = "${var.environment}-tege-packager-lambda-log-group"
  tege_packager_lambda_log_stream_name = "${var.environment}-tege-packager-lambda-logs"

  runocr_tesseract_lambda_log_group_name  = "${var.environment}-runocr-tesseract-lambda-log-group"
  runocr_tesseract_lambda_log_stream_name = "${var.environment}-runocr-tesseract-lambda-logs"

  #Lambda function name
  runocr_tesseract_lambda_function = "${var.organization}-${var.environment}-${var.region}-runocr-tesseract-lambda-function"

  #Secret-Manager Naming convention resoution
  secret_manager_database_source = "${var.organization}-${var.environment}-${var.region}-ssm-key-rds"
  secret_manager_jwt_id          = "${var.organization}-${var.environment}-${var.region}-ssm-jwt-secret"

}
