"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def url_parse_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("url_parse_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.emailBody","artifact:*.id"])

    parameters = []

    # build parameters list for 'url_parse_1' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "input_url": container_artifact_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/url_parse", parameters=parameters, name="url_parse_1", callback=artifact_create_4)

    return


@phantom.playbook_block()
def artifact_create_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("artifact_create_4() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.cat","artifact:*.cef.cn1Label","artifact:*.id"])
    inputs_data_0 = phantom.collect2(container=container, datapath=["extract_email_1:artifact:*.cef.requestURL","extract_email_1:artifact:*.id"])
    url_parse_1__result = phantom.collect2(container=container, datapath=["url_parse_1:custom_function_result.data.output_url"])

    parameters = []

    # build parameters list for 'artifact_create_4' call
    for container_artifact_item in container_artifact_data:
        for inputs_item_0 in inputs_data_0:
            for url_parse_1__result_item in url_parse_1__result:
                parameters.append({
                    "container": container_artifact_item[0],
                    "name": "url",
                    "label": container_artifact_item[1],
                    "severity": "low",
                    "cef_field": inputs_item_0[0],
                    "cef_value": url_parse_1__result_item[0],
                    "cef_data_type": url_parse_1__result_item[0],
                    "tags": None,
                    "run_automation": True,
                    "input_json": url_parse_1__result_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create_4")

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.type", "==", "email"],
            ["artifact:*.data contains", "in", "\"http\""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_parse_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    url_parse_1__result = phantom.collect2(container=container, datapath=["url_parse_1:custom_function_result.data.output_url"])
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.vaultId"])

    url_parse_1_data_output_url = [item[0] for item in url_parse_1__result]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    output = {
        "urls": url_parse_1_data_output_url,
        "artifact_id": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return