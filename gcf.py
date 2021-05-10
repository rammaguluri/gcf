#*********Resources referrenced *****************************
# https://github.com/GoogleCloudPlatform/python-docs-samples/tree/045f999a22ce8aa2a4f5346b2252e48e8ca4e929/iam/api-client
# https://cloud.google.com/iam/docs/granting-changing-revoking-access

import base64
import googleapiclient.discovery
import json
def iamremediation(event, context):
    role_whitelist ="""
        {
            "roles/bigquery.dataEditor", "roles/compute.admin", "roles/bigquery.dataOwner", "roles/bigquery.connectionAdmin"
        }
    """

    """Triggered from a message on a Cloud Pub/Sub topic.
    Args:
         event (dict): Event payload.
         context (google.cloud.functions.Context): Metadata for the event.
    """
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    pubsubPayload = json.loads(pubsub_message)
    print(pubsubPayload)
    principal =  pubsubPayload["protoPayload"]["authenticationInfo"]["principalEmail"]
    bindingDeltas = pubsubPayload["protoPayload"]["serviceData"]["policyDelta"]["bindingDeltas"]
    projectID =  pubsubPayload["protoPayload"]["resourceName"].split("/")[1]
    
    print("projectID:" + projectID)
    print("principal:" +  principal)
    print("PolicyDeltas:" + json.dumps(bindingDeltas))
    iamPolicy = get_policy(projectID,"1")
    isRemediationRequired = "NO"
    for delta in bindingDeltas:
        if delta["action"] == "ADD":
            role = delta["role"]
            member = delta["member"]
            if json.dumps(role_whitelist).find(role) == -1:
               print("Remediation required for:" + json.dumps(delta))
               iamPolicy = modify_policy_remove_member(iamPolicy,role,member)
               isRemediationRequired = "YES"
            if isRemediationRequired == "YES":
                set_policy(projectID,iamPolicy)


    #updatedPolicy = modify_policy_remove_member(policy,"roles/iam.securityAdmin","user:ram@xpertintuit.com")
    #finalPolicy = set_policy("plasma-centaur-231114",updatedPolicy)
    #print(finalPolicy)
  
    # [START iam_get_policy]
def get_policy(project_id, version=1):
    """Gets IAM policy for a project."""
  
    service = googleapiclient.discovery.build(
        "cloudresourcemanager", "v1"
    )
    policy = (
        service.projects()
        .getIamPolicy(
            resource=project_id,
            body={"options": {"requestedPolicyVersion": version}},
        )
        .execute()
    )
      
    return policy

    request_json = request.get_json()
    if request.args and 'message' in request.args:
        return request.args.get('message')
    elif request_json and 'message' in request_json:
        return request_json['message']
    else:
        return f'Hello World!'

# [START iam_modify_policy_add_member]
def modify_policy_add_member(policy, role, member):
    """Adds a new member to a role binding."""

    binding = next(b for b in policy["bindings"] if b["role"] == role)
    binding["members"].append(member)
    print(binding)
    return policy

# [END iam_modify_policy_add_member]


# [START iam_modify_policy_add_role]
def modify_policy_add_role(policy, role, member):
    """Adds a new role binding to a policy."""

    binding = {"role": role, "members": [member]}
    policy["bindings"].append(binding)
    print(policy)
    return policy


# [END iam_modify_policy_add_role]


# [START iam_modify_policy_remove_member]
def modify_policy_remove_member(policy, role, member):
    """Removes a  member from a role binding."""
    binding = next(b for b in policy["bindings"] if b["role"] == role)
    if "members" in binding and member in binding["members"]:
        binding["members"].remove(member)
    print(binding)
    return policy


# [END iam_modify_policy_remove_member]


# [START iam_set_policy]
def set_policy(project_id, policy):
    """Sets IAM policy for a project."""

    service = googleapiclient.discovery.build(
             "cloudresourcemanager", "v1")
    policy = (
        service.projects()
        .setIamPolicy(resource=project_id, body={"policy": policy})
        .execute()
    )
    print(policy)
    return policy


# [END iam_set_policy]
