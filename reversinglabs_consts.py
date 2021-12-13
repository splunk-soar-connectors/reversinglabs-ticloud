# --
# File: reversinglabs_consts.py
#
# Copyright (c) ReversingLabs Inc 2016-2020
#
# This unpublished material is proprietary to ReversingLabs Inc.
# All rights reserved.
# Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of ReversingLabs Inc.
#
# --


# Status/Progress Messages
REVERSINGLABS_MSG_GOT_RESP = 'Got Response from ReversingLabs'
REVERSINGLABS_SUCC_MSG_OBJECT_QUERIED = 'ReversingLabs query for {object_name} \'{object_value}\' finished'
REVERSINGLABS_ERR_MSG_OBJECT_QUERIED = 'ReversingLabs query for {object_name} \'{object_value}\' failed'
REVERSINGLABS_MSG_CONNECTING_WITH_URL = 'Querying ReversingLabs REST API'
REVERSINGLABS_SUCC_CONNECTIVITY_TEST = 'Connectivity test passed'
REVERSINGLABS_ERR_CONNECTIVITY_TEST = 'Connectivity test failed'
REVERSINGLABS_MSG_CHECK_CREDENTIALS = 'Please check your credentials or the network connectivity'
REVERSINGLABS_ERR_INVALID_HASH = 'Invalid hash'
REVERSINGLABS_ERR_QUERY_FAILED = 'Query to check hash failed with HTTP return code {ret_code}'
REVERSINGLABS_GENERATED_RANDOM_HASH = 'Generated random hash for testing connectivity'

# Jsons used in params, result, summary etc.
REVERSINGLABS_JSON_DETECTIONS = 'detections'
REVERSINGLABS_JSON_FOUND = 'found'
REVERSINGLABS_JSON_POSITIVES = 'positives'
REVERSINGLABS_JSON_TOTAL_SCANS = 'total_scans'
REVERSINGLABS_JSON_TOTAL_POSITIVES = 'total_positives'
REVERSINGLABS_JSON_STATUS = 'status'
REVERSINGLABS_JSON_THREAT_NAME = 'threat_name'
REVERSINGLABS_JSON_ADVANCED_SEARCH = 'search_parameter'
REVERSINGLABS_JSON_URI = 'uri'
REVERSINGLABS_JSON_THUMBPRINT = 'thumbprint'
REVERSINGLABS_JSON_SAMPLE_TYPE = 'sample_type'
REVERSINGLABS_JSON_CLASSIFICATION = 'classification'
REVERSINGLABS_JSON_FACTOR = 'factor'
REVERSINGLABS_JSON_REASON = 'reason'
REVERSINGLABS_JSON_HUNTING_META = 'hunting_meta'
REVERSINGLABS_JSON_HUNTING_REPORT = 'hunting_report_vault_id'
REVERSINGLABS_JSON_JOE_REPORT = 'joe_report_vault_id'
REVERSINGLABS_JSON_CONCLUSION = 'conclusion'

# Other constants used in the connector
TICLOUD_AWS_HOST_NAME = 'https://ticloud-aws1-api.reversinglabs.com'

MAL_PRESENCE_API_URL = '/api/databrowser/malware_presence/bulk_query/json?extended=true&show_hashes=True'
XREF_API_URL = '/api/xref/v2/bulk_query/json'
ADVANCED_SEARCH_API_URL = '/api/search/v1/query'
RHA1_ANALYTICS_API_URL = '/api/rha1/analytics/v1/query/json'
MAX_SEARCH_RESULTS   = 1000
MAX_BULK_HASHES_RHA1 = 1000
MAX_BULK_HASHES_MWP  = 100
MAX_BULK_HASHES_CERT = 100
URI_STATISTICS_API_URL = '/api/uri/statistics/uri_state/sha1/{sha1}?format=json'
CERTIFICATE_ANALYTICS_URL = '/api/certificate/analytics/v1/query/thumbprint/json'

URI_ANALYTICS_EMPTY_COUNTERS = {'known': 0, 'malicious': 0, 'suspicious': 0}
