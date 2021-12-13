# --
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

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult
from phantom.vault import Vault

# THIS Connector imports
from reversinglabs_consts import *

# Other imports used by this connector
import json
import hashlib
import requests
import collections
from requests.auth import HTTPBasicAuth
from requests import HTTPError
from requests import ConnectionError

# Wheels import
from rl_threat_hunting import cloud
from rl_threat_hunting import constants
from rl_threat_hunting import file_report
from rl_threat_hunting import mwp_metadata_adapter
from rl_threat_hunting.plugins import joe_sandbox


class ReversinglabsConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_FILE_REPUTATION    = 'file_reputation'
    ACTION_ID_ADV_SEARHC         = 'adv_search'
    ACTION_ID_RHA1_ANALYTICS     = 'file_similarity'
    ACTION_ID_URI_STATISTICS     = 'uri_statistics'
    ACTION_ID_CERT_ANALYTICS     = 'certificate_analytics'
    ACTION_ID_ADD_JOE_RESULTS    = 'add_joe_results'

    def __init__(self):
        super(ReversinglabsConnector, self).__init__()

        self._headers            = {'content-type': 'application/octet-stream', 'User-Agent': 'ReversingLabs Phantom TiCloud v2.2'}
        self._auth               = None
        self._mwp_url            = TICLOUD_AWS_HOST_NAME + MAL_PRESENCE_API_URL
        self._xref_url           = TICLOUD_AWS_HOST_NAME + XREF_API_URL
        self._search_url         = TICLOUD_AWS_HOST_NAME + ADVANCED_SEARCH_API_URL
        self._rha1_url           = TICLOUD_AWS_HOST_NAME + RHA1_ANALYTICS_API_URL
        self._uri_statistics_url = TICLOUD_AWS_HOST_NAME + URI_STATISTICS_API_URL
        self._cert_analytics_url = TICLOUD_AWS_HOST_NAME + CERTIFICATE_ANALYTICS_URL
        self._verify_cert        = True

        self.ACTIONS = {
            phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY : self.action_asset_connectivity,
            self.ACTION_ID_FILE_REPUTATION            : self.action_file_reputation,
            self.ACTION_ID_ADV_SEARHC                 : self.action_advanced_search,
            self.ACTION_ID_RHA1_ANALYTICS             : self.action_file_similarity_analytics,
            self.ACTION_ID_URI_STATISTICS             : self.action_uri_statistics,
            self.ACTION_ID_CERT_ANALYTICS             : self.action_cert_analytics,
            self.ACTION_ID_ADD_JOE_RESULTS            : self.action_add_joe_results,
        }

    def initialize(self):
        config = self.get_config()
        
        self._auth = HTTPBasicAuth(
            phantom.get_req_value(config, phantom.APP_JSON_USERNAME),
            phantom.get_req_value(config, phantom.APP_JSON_PASSWORD),
        )

        if 'url' in config:
            base_url = config['url']
            self._mwp_url    = '{0}{1}'.format(base_url, MAL_PRESENCE_API_URL)
            self._xref_url   = '{0}{1}'.format(base_url, XREF_API_URL)
            self._search_url = '{0}{1}'.format(base_url, ADVANCED_SEARCH_API_URL)
            self._rha1_url   = '{0}{1}'.format(base_url, RHA1_ANALYTICS_API_URL)
            self._uri_statistics_url = '{0}{1}'.format(base_url, URI_STATISTICS_API_URL)
            self._cert_analytics_url = '{0}{1}'.format(base_url, CERTIFICATE_ANALYTICS_URL)

        if 'verify_server_cert' in config:
            self._verify_cert = config['verify_server_cert']

        self.debug_print('self.status', self.get_status())

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        action    = self.ACTIONS.get(action_id)
        if not action:
            return

        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            success_message = action(action_result, param)
        except requests.HTTPError as err:
            return action_result.set_status(phantom.APP_ERROR, 'Request to server failed. {}'.format(err))
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, str(err))

        if success_message:
            return action_result.set_status(phantom.APP_SUCCESS, success_message)

        return action_result.set_status(phantom.APP_SUCCESS)
    
    def action_advanced_search(self, action_result, param):
        hunting_report, vault_id = self._get_threat_hunting_state(param)
        single_search_term       = param.get(REVERSINGLABS_JSON_ADVANCED_SEARCH)
        results_per_page       = param.get("results_per_page")
        page_number       = param.get("page_number")

        if hunting_report:
            self._hunting_with_advanced_search(action_result, hunting_report, vault_id)
        elif single_search_term:
            self._advanced_search_make_single_query(action_result, single_search_term, results_per_page, page_number)
        else:
            raise ApplicationExecutionFailed('No parameters provided. At least one is needed.')

    def _hunting_with_advanced_search(self, action_result, hunting_report, vault_id):
        search_tasks = cloud.get_query_tasks(hunting_report, constants.HuntingCategory.ADVANCED_SEARCH)

        if not search_tasks:
            self._update_threat_hunting_state(action_result, hunting_report, vault_id)
            return

        for task in search_tasks:
            search_term = task['query']['term']

            if 'classification:' in search_term:
                search_function = self._make_search_api_request
            else:
                search_function = self._make_double_search_api_request

            try:
                api_data = search_function(search_term)
            except (HTTPError, ConnectionError):
                cloud.mark_tasks_as_failed(hunting_report, task)
                continue

            try:
                cloud.update_hunting_meta(hunting_report, api_data, task)
            except StopIteration:
                break

        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
        self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

    def _make_double_search_api_request(self, task_term):
        api_data = tuple()
        for search_term  in [task_term + ' AND classification:malicious',
                             task_term + ' AND classification:known']:
            response = self._make_search_api_request(search_term)
            api_data += (response,)
        return api_data

    def _advanced_search_make_single_query(self, action_result, search_term, results_per_page, page_number):
        api_data = self._make_search_api_request(search_term, results_per_page, page_number)
        action_result.add_data(api_data)

    def _make_search_api_request(self, search_term, results_per_page, page_number):
        post_data = {'query': search_term, 'format': 'json', 'page': page_number or 1, 'records_per_page': results_per_page or MAX_SEARCH_RESULTS}
        response  = requests.post(self._search_url,
                                  data=json.dumps(post_data),
                                  auth=self._auth, headers=self._headers, verify=self._verify_cert)

        if response.ok:
            return self._parse_json(response)

        response.raise_for_status()
        
    @staticmethod
    def _parse_json(response):
        try:
            return response.json(object_pairs_hook=file_report.encode_unicode_utf8)
        except Exception as err:
            raise ApplicationExecutionFailed('Response does not seem to be a valid JSON. {}'.format(err))

    def action_file_similarity_analytics(self, action_result, param):
        hunting_report, vault_id     = self._get_threat_hunting_state(param)
        single_hash_value, rha1_type = self._get_single_file_similarity_parameter(param)

        if hunting_report:
            self._hunting_with_file_similarity(action_result, hunting_report, vault_id)
        elif single_hash_value:
            self._file_similarity_make_single_query(action_result, single_hash_value, rha1_type)
        else:
            raise ApplicationExecutionFailed('No parameters provided. At least one is needed.')

    def _get_single_file_similarity_parameter(self, parameters):
        sha1_value  = parameters.get(phantom.APP_JSON_HASH)
        sample_type = parameters.get(REVERSINGLABS_JSON_SAMPLE_TYPE)

        if not sha1_value and not sample_type:
            return None, None

        if not phantom.is_sha1(sha1_value):
            raise ApplicationExecutionFailed('Provided file hash must be SHA1.')

        rha1_type = self._get_rha1_type(sample_type)
        if not rha1_type:
            raise ApplicationExecutionFailed(
                'Invalid file type for RHA1 analytics. Only PE, ELF and MachO files are supported')

        return sha1_value, rha1_type

    @staticmethod
    def _get_rha1_type(sample_type):
        if sample_type.startswith('MachO'):
            return 'macho01'
        if sample_type.startswith('ELF'):
            return 'elf01'
        if sample_type.startswith('PE'):
            return'pe01'

    def _hunting_with_file_similarity(self, action_result, hunting_report, vault_id):
        file_similarity_tasks = cloud.get_query_tasks(hunting_report, constants.HuntingCategory.FILE_SIMILARITY_ANALYTICS)

        if not file_similarity_tasks:
            self._update_threat_hunting_state(action_result, hunting_report, vault_id)
            return

        categorized_file_similarity_tasks = self._categorize_file_similarity_tasks(file_similarity_tasks)

        for rha1_type in categorized_file_similarity_tasks:
            tasks  = categorized_file_similarity_tasks[rha1_type]

            for tasks_batch in self.make_batches(tasks, MAX_BULK_HASHES_RHA1):
                terms  = [task['query']['term'] for task in tasks_batch]
                hashes = [term.split('/')[1] for term in terms]

                try:
                    api_data = self._make_file_similarity_post_api_request(rha1_type, hashes)
                except (HTTPError, ConnectionError):
                    cloud.mark_tasks_as_failed(hunting_report, *tasks_batch)
                    continue

                cloud.update_hunting_meta(hunting_report, api_data, *tasks_batch)

        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
        self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

    @staticmethod
    def _categorize_file_similarity_tasks(file_similarity_tasks):
        categorized_tasks = collections.defaultdict(list)
        for task in file_similarity_tasks:
            term = task['query']['term']
            rha1_type, _ = term.split('/')
            categorized_tasks[rha1_type].append(task)
        return categorized_tasks

    def _file_similarity_make_single_query(self, action_result, hash_value, rha1_type):
        api_data = self._make_file_similarity_post_api_request(rha1_type, [hash_value])
        action_result.add_data(api_data)

    def _make_file_similarity_post_api_request(self, rha1_type, hashes):
        post_data = {'rl': {'query': {'rha1_type': rha1_type, 'extended': 'true', 'response_format': 'json', 'hashes': hashes}}}
        response  = requests.post(self._rha1_url,
                                  data=json.dumps(post_data),
                                  auth=self._auth, headers=self._headers, verify=self._verify_cert)

        if response.ok or response.status_code == requests.status_codes.codes.NOT_FOUND:
            return self._parse_json(response)

        response.raise_for_status()

    def action_uri_statistics(self, action_result, param):
        hunting_report, vault_id = self._get_threat_hunting_state(param)
        uri_term                 = param.get(REVERSINGLABS_JSON_URI)

        if hunting_report:
            self._hunting_with_uri_statistics(action_result, hunting_report, vault_id)
        elif uri_term:
            self._uri_statistics_make_single_query(action_result, uri_term)
        else:
            raise ApplicationExecutionFailed('No parameters provided. At least one is needed.')

    def _hunting_with_uri_statistics(self, action_result, hunting_report, vault_id):
        uri_tasks = cloud.get_query_tasks(hunting_report, constants.HuntingCategory.URI_ANALYTICS)

        if not uri_tasks:
            self._update_threat_hunting_state(action_result, hunting_report, vault_id)
            return

        for task in uri_tasks:
            uri_term = task['query']['term']

            try:
                api_data = self._make_uri_statistics_api_request(uri_term)
            except (HTTPError, ConnectionError):
                cloud.mark_tasks_as_failed(hunting_report, task)
                continue

            cloud.update_hunting_meta(hunting_report, api_data, task)

        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
        self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

    def _uri_statistics_make_single_query(self, action_result, uri_term):
        api_data = self._make_uri_statistics_api_request(uri_term)
        action_result.add_data(api_data)

    def _make_uri_statistics_api_request(self, uri_term):
        uri_sha1 = self._generate_sha1_hash(uri_term)
        uri_request_url = self._uri_statistics_url.format(sha1=uri_sha1)
        response = requests.get(uri_request_url, auth=self._auth, headers=self._headers, verify=self._verify_cert)

        if response.ok:
            return self._parse_json(response)
        elif response.status_code == requests.status_codes.codes.NOT_FOUND:
            return None

        response.raise_for_status()

    def action_cert_analytics(self, action_result, param):
        hunting_report, vault_id = self._get_threat_hunting_state(param)
        thumbprint_value         = param.get(REVERSINGLABS_JSON_THUMBPRINT)

        if hunting_report:
            self._hunting_with_certificate_analytics(action_result, hunting_report, vault_id)
        elif thumbprint_value:
            self._cert_analytics_make_single_query(action_result, thumbprint_value)
        else:
            raise ApplicationExecutionFailed('No parameters provided. At least one is needed.')

    def _hunting_with_certificate_analytics(self, action_result, hunting_report, vault_id):
        cert_tasks = cloud.get_query_tasks(hunting_report, constants.HuntingCategory.CERTIFICATE_ANALYTICS)

        if not cert_tasks:
            self._update_threat_hunting_state(action_result, hunting_report, vault_id)
            return

        for tasks_bulk in self.make_batches(cert_tasks, MAX_BULK_HASHES_CERT):
            thumbprints = [task['query']['term'] for task in tasks_bulk]

            try:
                api_data = self._make_certificate_analytics_api_request(thumbprints)
            except (HTTPError, ConnectionError):
                cloud.mark_tasks_as_failed(hunting_report, *tasks_bulk)
                continue

            cloud.update_hunting_meta(hunting_report, api_data, *tasks_bulk)

        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
        self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

    def _cert_analytics_make_single_query(self, action_result, thumbprint):
        api_data = self._make_certificate_analytics_api_request([thumbprint])
        action_result.add_data(api_data)

    def _make_certificate_analytics_api_request(self, thumpbrints):
        post_data = {'rl': {'query': {'thumbprints': thumpbrints, 'format': 'json'}}}
        response = requests.post(self._cert_analytics_url,
                                 data=json.dumps(post_data),
                                 auth=self._auth, headers=self._headers, verify=self._verify_cert)

        if response.ok:
            return self._parse_json(response)

        response.raise_for_status()

    @staticmethod
    def _determine_valid_hash_type(value):
        if phantom.is_md5(value):
            return 'md5'
        if phantom.is_sha1(value):
            return 'sha1'
        if phantom.is_sha256(value):
            return 'sha256'
        raise ApplicationExecutionFailed('Must be valid MD5, SHA1 or SHA256 hash value.')

    def action_asset_connectivity(self, action_result, param):
        # just MWP for now, need to test other APIs, at least one should work.

        sha1_hash = self._generate_random_sha1_hash()
        self.save_progress(REVERSINGLABS_GENERATED_RANDOM_HASH)

        query    = {'rl': {'query': {'hash_type': 'sha1', 'hashes': [sha1_hash]}}}
        response = requests.post(self._mwp_url, auth=self._auth, json=query,
                                 headers=self._headers, verify=self._verify_cert)

        if not response.ok:
            self.set_status(phantom.APP_ERROR)
            status_message = '{0}. {1}. HTTP status_code: {2}, reason: {3}'.format(
                REVERSINGLABS_ERR_CONNECTIVITY_TEST, REVERSINGLABS_MSG_CHECK_CREDENTIALS,
                response.status_code, response.reason
            )
            self.append_to_message(status_message)
            self.append_to_message(self._mwp_url)
            return self.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, REVERSINGLABS_SUCC_CONNECTIVITY_TEST)

    @classmethod
    def _generate_random_sha1_hash(cls):
        random_string = phantom.get_random_chars(size=10)
        return cls._generate_sha1_hash(random_string)

    @staticmethod
    def _generate_sha1_hash(value):
        sha1 = hashlib.sha1(value)
        return sha1.hexdigest()

    def action_file_reputation(self, action_result, param):
        hunting_report, vault_id     = self._get_threat_hunting_state(param)
        single_hash_value, hash_type = self._get_single_hash_parameter(param)

        if hunting_report:
            self._hunt_with_file_reputation(action_result, hunting_report, vault_id)
        elif single_hash_value:
            self._file_reputation_creates_new_hunting_state(action_result, hash_type, single_hash_value)
        else:
            raise ApplicationExecutionFailed('No parameters provided. At least one is needed.')

    def _get_single_hash_parameter(self, parameters):
        hash_value = parameters.get(phantom.APP_JSON_HASH)
        if hash_value:
            hash_type = self._determine_valid_hash_type(hash_value)
            return hash_value, hash_type
        return None, None

    def _hunt_with_file_reputation(self, action_result, hunting_report, vault_id):
        reputation_tasks = cloud.get_query_tasks(hunting_report, constants.HuntingCategory.CLOUD_REPUTATION)

        if not reputation_tasks:
            self._update_threat_hunting_state(action_result, hunting_report, vault_id)
            return

        categorized_file_reputation_tasks = self._categorize_file_reputation_tasks(reputation_tasks)

        for hash_type in categorized_file_reputation_tasks:
            tasks = categorized_file_reputation_tasks[hash_type]

            for tasks_batch in self.make_batches(tasks, MAX_BULK_HASHES_MWP):
                hashes = [task['query']['term'] for task in tasks_batch]

                try:
                    api_data = self._make_file_reputation_api_request(hash_type, hashes)
                except (HTTPError, ConnectionError):
                    cloud.mark_tasks_as_failed(hunting_report, *tasks_batch)
                    continue

                cloud.update_hunting_meta(hunting_report, api_data, *tasks_batch)

        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
        self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

    def _categorize_file_reputation_tasks(self, query_tasks):
        categorized_tasks = {}
        for task in query_tasks:
            hash_value = task['query']['term']
            hash_type  = self._determine_valid_hash_type(hash_value)

            category_hashes = categorized_tasks.setdefault(hash_type, [])
            category_hashes.append(task)

        return categorized_tasks

    def _file_reputation_creates_new_hunting_state(self, action_result, hash_type, hash_value):
        api_data       = self._make_file_reputation_api_request(hash_type, [hash_value])
        hunting_report = mwp_metadata_adapter.parse_mwp_metadata(api_data)

        hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
        self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

    def _make_file_reputation_api_request(self, hash_type, hashes):
        post_data = {'rl': {'query': {'hash_type': hash_type, 'hashes': hashes}}}
        response  = requests.post(self._mwp_url,
                                  data=json.dumps(post_data),
                                  auth=self._auth, headers=self._headers, verify=self._verify_cert)

        if response.ok:
            return self._parse_json(response)

        response.raise_for_status()

    def action_add_joe_results(self, action_result, param):
        hunting_report, vault_id = self._get_threat_hunting_state(param)
        joe_report_vault_id      = param.get(REVERSINGLABS_JSON_JOE_REPORT)

        if not hunting_report and not joe_report_vault_id:
            raise ApplicationExecutionFailed('Parameters not provided')

        joe_report = None
        if joe_report_vault_id:
            joe_report_path = Vault.get_file_path(joe_report_vault_id)

            with open(joe_report_path, 'r') as joe_file:
                joe_report = json.load(joe_file)

        if hunting_report:
            joe_sandbox.add_dynamic_analysis(hunting_report, joe_report)
            hunting_meta_vault_id = self._store_threat_hunting_state(hunting_report)
            self._update_threat_hunting_state(action_result, hunting_report, hunting_meta_vault_id)

        else:
            action_result.add_data({'joe_report': joe_report})

    def finalize(self):
        total_positives = 0
        for action_result in self.get_action_results():
            action_id = self.get_action_identifier()

            if action_id == self.ACTION_ID_FILE_REPUTATION:
                self._update_summary_for_file_reputation(action_result, total_positives)

    def _update_summary_for_file_reputation(self, action_result, total_positives):
        summary = action_result.get_summary()

        positive_detections = summary.get(REVERSINGLABS_JSON_POSITIVES)
        if positive_detections:
            total_positives += 1
            self.update_summary({REVERSINGLABS_JSON_TOTAL_POSITIVES: total_positives})

    @staticmethod
    def make_batches(data, max_length):
        number_of_batches = xrange(0, len(data), max_length)
        for start_index in number_of_batches:
            end_index = start_index + max_length
            yield data[start_index:end_index]

    @staticmethod
    def _get_threat_hunting_state(parameters):
        hunting_report_vault_id = parameters.get(REVERSINGLABS_JSON_HUNTING_REPORT)
        if hunting_report_vault_id:
            hunting_report_file_path = Vault.get_file_path(hunting_report_vault_id)
            hunting_report = file_report.read_json(hunting_report_file_path)

            return hunting_report, hunting_report_vault_id

        return None, None

    def _store_threat_hunting_state(self, hunting_meta):
        container_id    = self.get_container_id()
        vault_file_name = self._create_hunting_report_name()
        dump_path       = self._dump_report_in_file(hunting_meta, vault_file_name)
        created_info    = Vault.add_attachment(dump_path, container_id, file_name=vault_file_name)

        if created_info.get('succeeded'):
            return created_info.get('vault_id')

        raise VaultError('Storing threat hunting report failed.')

    def _create_hunting_report_name(self):
        product_name = self._get_product_name()
        action_name  = self._get_action_name()
        return '{}_{}_hunting_report.json'.format(product_name, action_name)

    def _get_product_name(self):
        app_config   = self.get_app_json()
        product_name = app_config['product_name']
        return product_name.replace(' ', '_')

    def _get_action_name(self):
        action_name = self.get_action_name()
        return action_name.replace(' ', '_')

    @staticmethod
    def _dump_report_in_file(hunting_meta, file_name):
        dump_dir  = Vault.get_vault_tmp_dir()
        dump_path = '{}/{}'.format(dump_dir, file_name)
        return file_report.write_json(hunting_meta, dump_path)

    @staticmethod
    def _update_threat_hunting_state(action_result, hunting_report, hunting_report_vault_id):
        action_result.add_data(hunting_report)
        action_result.add_data({REVERSINGLABS_JSON_HUNTING_REPORT: hunting_report_vault_id})


class ApplicationExecutionFailed(Exception):
    pass


class VaultError(Exception):
    pass


def test_with_action_json():
    import argparse

    parser = argparse.ArgumentParser('Test arguments')
    parser.add_argument('input_json', help='Input action json file path.')
    parser.add_argument('-p', '--pudb', required=False, action='store_true', help='Use visual python debugger.')
    args = parser.parse_args()

    if args.pudb:
        import pudb
        pudb.set_trace()

    with open(args.input_json) as action_input_json:
        input_data = json.loads(action_input_json.read())

    print json.dumps(input_data, indent=4)

    connector = ReversinglabsConnector()
    connector.print_progress_message = True

    action_result_text = connector._handle_action(json.dumps(input_data), None)
    try:
        action_result = json.loads(action_result_text)
        print json.dumps(action_result, indent=4)
    except TypeError:
        print action_result_text


if __name__ == '__main__':
    # create test json for specific action before it can be run
    # phenv python2.7 /opt/phantom/bin/create_tj.pyc 'file similarity analytics'

    # phenv python2.7 reversinglabs_connector.py /tmp/rltitaniumcloudrestapis-file_similarity_analytics.json
    # phenv python2.7 reversinglabs_connector.py /tmp/rltitaniumcloudrestapis-file_reputation.json
    # phenv python2.7 reversinglabs_connector.py /tmp/rltitaniumcloudrestapis-advanced_search.json
    # phenv python2.7 reversinglabs_connector.py /tmp/rltitaniumcloudrestapis-uri_statistics.json
    # phenv python2.7 reversinglabs_connector.py /tmp/rltitaniumcloudrestapis-certificate_analytics.json

    test_with_action_json()
