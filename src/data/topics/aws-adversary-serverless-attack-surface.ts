import type { Topic } from '@/types'

export const topic: Topic = {
  slug: 'aws/adversary/serverless-attack-surface',
  title: 'Serverless attack surface',
  cloud: 'aws',
  stage: 'adversary',
  track: 'Compute',
  summary:
    'Lambda and the event sources around it: how untrusted data gets a function to run, and what the execution role gives the attacker when it does.',
  duration: '35 min',
  difficulty: 4,
  prerequisites: [
    'aws/operator/compute-and-containers',
    'aws/foundation/identity-and-trust',
  ],
  enables: [
    'aws/redteam/iam-privilege-escalation',
    'aws/redteam/attack-path-chaining',
  ],
  mentalModel:
    'Serverless has no servers to patch and a very large number of ways in. The function code is rarely the weak point — the trigger, the execution role and the exposed HTTP endpoint are.',
  concept: {
    body: `Serverless shifts the attack surface from the machine to the *event*. There is no server to patch, no open port to scan and no patch window. What remains is a set of triggers, each of which accepts data from somewhere, and a function that runs with a fixed identity.

**The trigger surface.** Every Lambda function has zero or more event source mappings, and each one is a way to make your code run:

- *S3 events* — an object created in a bucket invokes the function. Anyone who can write to the bucket can run your code.
- *SQS and SNS* — a message on a queue or a topic invokes the function. Queue and topic policies decide who can send.
- *EventBridge and CloudWatch Events* — an event matching a pattern invokes the function. A schedule rule with a wildcard pattern is an invitation.
- *DynamoDB streams, Kinesis, MSK, SQS* — same idea.
- *API Gateway and function URLs* — the function is an HTTP endpoint. This is the most direct and the most under-tested.

**The identity.** Each function has an execution role. Whatever that role can do, the attacker can do from inside the function. Lambda execution roles commonly accumulate permissions because the pattern "the function needed access to X once" never gets cleaned up.

**The configuration surface.** Environment variables (readable in plaintext by anyone with GetFunctionConfiguration), layers (shared code that executes inside your function's environment and can see your environment variables), and the function's VPC configuration (which determines whether the metadata service is reachable).

**The exposure surface.** Function URLs and API Gateway expose the function to the internet, and their authentication is independent of IAM. A function URL with \`AuthType: NONE\` is a public HTTP endpoint whose code runs with your execution role. An API Gateway REST API with no authorizer is the same thing with more steps.

**The infrastructure surface.** Step Functions, API Gateway, EventBridge rules, SQS queues, SNS topics, CloudFormation, CodeBuild, Glue, Athena. Each is a resource with its own policy and its own way to be abused, and several of them — CodeBuild and CloudFormation in particular — let you run code as a role you cannot assume.

The practical difference from traditional infrastructure is that **the function is not the perimeter**. The perimeter is the trigger and the endpoint.`,
    keyPoints: [
      'Anyone who can write to a triggering bucket, publish to a topic or send to a queue can cause your function to run.',
      'The execution role is the whole privilege boundary for the function. Scope it to what the code does, not to what the project once needed.',
      'Environment variables are readable in plaintext by anyone with lambda:GetFunctionConfiguration.',
      'Function URLs and API Gateway have their own authentication, independent of IAM. A public endpoint runs your code with your role.',
      'Lambda layers execute inside the function environment and can read the function\'s environment variables.',
      'CodeBuild, Glue, CloudFormation and Step Functions can all run code as a role, which makes them serverless escalation primitives.',
    ],
    misconceptions: [
      {
        claim: 'Serverless has no attack surface because there is no server.',
        truth:
          'The attack surface moved to the triggers, the endpoints and the identity. It did not shrink. It became harder to see, because there is no host to log into and no process list to inspect.',
      },
      {
        claim: 'Because the function runs in the caller\'s context, IAM does not apply.',
        truth:
          'The opposite. The function runs under its execution role, not the caller\'s. IAM applies to that role, and the role\'s permissions are what the attacker inherits.',
      },
      {
        claim: 'A function URL behind an API Gateway authorizer is safe if the authorizer checks authentication.',
        truth:
          'Authentication is not authorization. An authorizer that verifies a valid token but does not check whether that token\'s subject may call that method and that resource leaves the IDOR in place.',
      },
    ],
  },
  attack: {
    body: `Serverless attacks come in four families, and they are worth separating because the detection and the fix differ for each.

**Family one: event injection.** The attacker writes data into something the function consumes. The function then processes attacker-controlled input with a privileged role. The classic example is an S3-triggered function that processes uploaded files: write a malicious file, and the function runs your parser with the execution role. The impact depends on what the function does with the input and what the role can do — and a lambda with \`lambda:CreateFunction\` and \`iam:PassRole\` is an escalation from the first execution.

**Family two: endpoint abuse.** The function is exposed over HTTP and the endpoint lacks proper authorisation. This is the classic serverless IDOR: an API Gateway method that checks that a JWT is valid but not that it covers the resource in the path. The attack is to call the method with a valid token belonging to another tenant.

**Family three: privilege escalation through the function.** The function's execution role has permissions the attacker can leverage — creating other functions with a privileged role, passing a role to another service, or reading a secret. This is where serverless meets the IAM privilege escalation material.

**Family four: secret exposure.** Environment variables, layers and the function's own logs can contain secrets. A function that logs its configuration, or that reflects its environment into an error message, leaks the credential that was supposed to be its protection.

A fifth pattern deserves a note: **event-driven lateral movement.** An SQS queue that receives messages from a producer in another account, whose trust policy is broad, lets an attacker in that account inject events into your processing pipeline. The queue policy is the trust boundary, and it is checked far less often than the IAM policy.`,
    techniques: [
      {
        name: 'Enumerate every function, its role, its triggers and its endpoints',
        what: 'Map the whole serverless surface of the account.',
        steps: [
          '`aws lambda list-functions --query "Functions[].[FunctionName,Role,Runtime,PackageType]"`.',
          '`aws lambda list-event-source-mappings` for the triggers.',
          '`aws lambda get-function-url-config` and `aws apigatewayv2 get-apis` for the exposed endpoints.',
          '`aws lambda get-policy` for the resource policies attached to functions.',
        ],
        command:
          'aws lambda list-functions --query "Functions[].[FunctionName,Role,PackageType,Runtime]" --output table',
        impact:
          'A complete list of what runs, as what, and where it can be reached from. This is the serverless equivalent of a port scan.',
      },
      {
        name: 'Read the function configuration and environment',
        what: 'Pull the environment variables and settings of a target function.',
        command:
          'aws lambda get-function-configuration --function-name payments --query "{Role:Role,Env:Environment.Variables,Vpc:VpcConfig,Timeout:Timeout,Memory:MemorySize}"',
        impact:
          'Environment variables in plaintext, the VPC configuration that determines metadata reachability, and the role that holds the real permissions.',
      },
      {
        name: 'Find a function URL with no authentication',
        what: 'Identify an internet-reachable function endpoint with no authorizer.',
        command:
          'aws lambda list-functions --query "Functions[].FunctionName" --output text | xargs -I{} aws lambda get-function-url-config --function-name {}',
        impact:
          'A public HTTP endpoint that runs your code with your execution role. Any input-validation bug in that code is now remotely exploitable.',
      },
      {
        name: 'Inject an event through a queue or topic',
        what: 'Send a message into the pipeline that triggers the function.',
        steps: [
          'Find the queue or topic: `aws sqs list-queues` and `aws sns list-topics`.',
          'Check the queue or topic policy for who may send.',
          'Send a crafted message that the function will process.',
        ],
        command:
          'aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123456789012/orders --message-body \'{"id":"attacker","action":"process"}\'',
        impact:
          'Your function runs attacker-controlled input with your execution role. If the function shells out, parses XML, or calls a downstream service with the message contents, you have code execution as the function.',
      },
      {
        name: 'Write into a bucket that triggers a function',
        what: 'Trigger a function by creating an object in its source bucket.',
        command:
          'aws s3 cp payload.json s3://uploads/incoming/20261121-job.json',
        impact:
          'The function executes on your object. If the function trusts the bucket contents, that is code execution — or at minimum, attacker-controlled data processed with the function\'s role.',
      },
      {
        name: 'Use the function as a privilege escalation primitive',
        what: 'Create a new function with a more privileged execution role.',
        steps: [
          'Confirm the target function\'s role holds `lambda:CreateFunction` and `iam:PassRole`.',
          'Create a new function whose role is the privileged one you cannot assume directly.',
          'Invoke it with code that returns the credentials from inside the execution environment.',
        ],
        command:
          'aws lambda create-function --function-name runner \\\n  --runtime python3.12 --role arn:aws:iam::123456789012:role/DeployAdmin \\\n  --handler index.handler --zip-file fileb://payload.zip',
        impact:
          'The privileged role\'s credentials, obtained from inside the serverless sandbox without ever passing an authorization check against it directly.',
      },
      {
        name: 'Read the function\'s own logs',
        what: 'Read CloudWatch Logs for the function, which frequently contain data and occasionally secrets.',
        command:
          'aws logs filter-log-events --log-group-name /aws/lambda/orders --start-time 1700000000000 --filter-pattern "" --limit 100',
        impact:
          'Whatever the function logs, including request payloads and, in the recurring failure mode, the connection string or token that was in the environment.',
      },
    ],
    cases: [
      {
        title: 'Event-driven execution of attacker-supplied data',
        source: 'Recurring pattern in published cloud assessment findings and public breach write-ups',
        impact:
          'In the recurring pattern, a file uploaded to a bucket triggered a processing function that was over-privileged and that trusted the file contents. The result was code execution inside a function that held permissions the application itself never needed.',
        year: 2022,
      },
    ],
  },
  detect: {
    body: `Serverless detection has three layers: what changed, what ran, and what the role did.

**What changed** is CloudTrail management events: \`CreateFunction\`, \`UpdateFunctionCode\`, \`AddPermission\`, \`CreateFunctionUrlConfig\`, \`UpdateFunctionUrlConfig\`, \`PutFunctionConcurrency\`, \`CreateEventSourceMapping\`, and \`CreateEventBusPolicy\`.

**What ran** is CloudWatch Logs for the function. The \`REPORT\` line at the end of each invocation gives duration, memory used, billed duration and, for error invocations, the error type. A function that has never errored starting to error is a lead.

**What the role did** is CloudTrail events where \`userIdentity.type\` is \`AssumedRole\` and the role is a function's execution role. This is the important one, because it is where serverless activity becomes a cloud attack. Look for Lambda execution roles appearing in IAM, STS, Secrets Manager, S3 or EC2 events that are not part of the function\'s job.

Two more signals worth having: functions with \`AuthType: NONE\` URLs, and queue/topic policies that allow a broad principal to send.`,
    signals: [
      {
        signal: 'A function was created, updated or made public',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.functionName, requestParameters.authType\n| filter eventName = "CreateFunction" or eventName = "UpdateFunctionCode" or eventName = "CreateFunctionUrlConfig" or eventName = "UpdateFunctionUrlConfig" or eventName = "AddPermission"\n| stats count() by eventName, userIdentity.arn, requestParameters.functionName`,
        note:
          'UpdateFunctionCode is how a foothold becomes persistent. AddPermission with a principal you did not expect is how an attacker gives themselves a way in.',
      },
      {
        signal: 'A Lambda execution role touched IAM, STS or Secrets Manager',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, eventSource, userIdentity.arn, requestParameters.secretId\n| filter userIdentity.type = "AssumedRole"\n| filter eventSource in ["iam.amazonaws.com","sts.amazonaws.com","secretsmanager.amazonaws.com"]\n| stats count() by userIdentity.arn, eventName`,
        note:
          'A function that reads a secret it does not need, or that calls STS, is either misconfigured or being used as an escalation step.',
      },
      {
        signal: 'A message was injected into a queue or topic',
        source: 'CloudTrail — management events',
        query: `fields @timestamp, eventName, userIdentity.arn, requestParameters.queueUrl, requestParameters.topicArn\n| filter eventName = "SendMessage" or eventName = "SendMessageBatch" or eventName = "Publish"\n| stats count() by userIdentity.arn, eventSource`,
        note:
          'Baseline the senders per queue. A new sender on a production queue is either a new integration or an injection attempt.',
      },
      {
        signal: 'An object was written to a bucket that has a Lambda trigger',
        source: 'CloudTrail — S3 data events / S3 server access logs',
        query: `fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName, requestParameters.key\n| filter eventName = "PutObject" and requestParameters.bucketName = "uploads"\n| stats count() by sourceIPAddress, requestParameters.key`,
        note:
          'Requires S3 data events. The interesting subset is uploads from an identity that does not normally write to that bucket.',
      },
      {
        signal: 'Function invocation errors increased sharply',
        source: 'CloudWatch Logs — Lambda log group',
        query: `fields @timestamp, @message\n| filter @message like /ERROR|Traceback|Exception/\n| stats count() by bin(5m)`,
        note:
          'A burst of errors on a function that was previously clean suggests someone is probing its input handling.',
      },
      {
        signal: 'Guardrail — require authorisation on function URLs and API Gateway methods',
        source: 'AWS Config managed rule / SCP',
        query: `SCP Deny: lambda:CreateFunctionUrlConfig and lambda:UpdateFunctionUrlConfig with authType NONE, except for functions tagged as public`,
        note:
          'This closes the unauthenticated HTTP surface at the platform level rather than relying on a review.',
      },
    ],
    posture: [
      'Never expose a function over HTTP without an authorizer, and make sure the authorizer checks authorisation and not just authentication.',
      'Enable CloudTrail data events for Lambda so invocations are recorded alongside the management events.',
      'Give every function its own execution role, scoped to the exact resources the code touches.',
      'Set a concurrency limit and a reserved concurrency on functions that should not be scaled by an attacker\'s input.',
      'Log the function name, the invoking principal and the request identifiers, and make sure request payloads are not logged verbatim.',
      'Review queue and topic policies on a schedule; they are resource policies and they are usually forgotten.',
    ],
  },
  fix: {
    body: `Serverless hardening follows the same pattern as the rest of AWS: reduce the trust in the trigger, reduce the value of the role, and remove the unauthenticated surface.

**Triggers.** Every event source should have a policy that names who may write. An S3 bucket that triggers a function should have a bucket policy that limits writes to the specific service or account that legitimately produces the object, and the function should validate the object's provenance regardless.

**Roles.** One execution role per function, scoped to the resources the function uses. Where the function needs a broad read, use a permission boundary. Where it needs a KMS key, scope the key policy too.

**Endpoints.** Where an HTTP interface is needed, put API Gateway with a JWT authorizer in front of it, and make the authorizer check the subject against the resource. Where a function URL is used, use a private endpoint with \`AuthType: AWS_IAM\`.

**Persistence.** Deny \`lambda:CreateFunction\`, \`lambda:UpdateFunctionCode\` and \`lambda:AddPermission\` outside the deployment identity. This is the control that stops a serverless foothold from becoming permanent.`,
    remediations: [
      {
        priority: 'critical',
        action: 'Scope every Lambda execution role to the resources the function actually uses',
        detail:
          'Split the role per function, not per project. A function that reads one bucket and sends one message should have exactly those two permissions and a permission boundary on top.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::app-data/orders/*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'critical',
        action: 'Replace unauthenticated function URLs with AWS_IAM auth or an API Gateway authorizer',
        detail:
          'A function URL with AuthType NONE is a public endpoint. If IAM authentication is enabled, the endpoint requires a signed SigV4 request, which is much harder to abuse than an open URL.',
        snippet: `aws lambda create-function-url-config --function-name orders \\\n  --auth-type AWS_IAM --invoke-mode BUFFERED`,
        snippetLang: 'bash',
      },
      {
        priority: 'high',
        action: 'Restrict who can send to the queues and topics that trigger functions',
        detail:
          'Queue and topic policies are resource policies and they are the trust boundary for event-driven pipelines. Name the producers instead of using a wildcard principal.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/OrderProducer" },
    "Action": "sqs:SendMessage",
    "Resource": "arn:aws:sqs:us-east-1:123456789012:orders"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Remove lambda:CreateFunction, lambda:UpdateFunctionCode and lambda:AddPermission from application roles',
        detail:
          'These three actions are the serverless persistence and escalation primitives. An SCP that denies them outside the deployment identity removes the entire class, regardless of what the IAM policy says.',
        snippet: `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["lambda:CreateFunction", "lambda:UpdateFunctionCode",
               "lambda:AddPermission", "lambda:CreateFunctionUrlConfig"],
    "Resource": "*"
  }]
}`,
        snippetLang: 'json',
      },
      {
        priority: 'high',
        action: 'Move secrets out of environment variables',
        detail:
          'Environment variables are readable in plaintext by anyone with GetFunctionConfiguration, and they are visible in the console and in the CLI. Use Secrets Manager and grant only GetSecretValue on the specific secret.',
      },
      {
        priority: 'medium',
        action: 'Validate event payload provenance inside the function',
        detail:
          'The trigger policy limits who can write, but the function should still check the object\'s key prefix, its content type and its size before processing it. Belt and braces, because the policy can be wrong.',
      },
      {
        priority: 'medium',
        action: 'Set reserved concurrency and a maximum timeout',
        detail:
          'Reserved concurrency caps how much of the account\'s concurrency a single function can consume, which limits the blast radius of an event flood and of an accidental infinite loop.',
        snippet: `aws lambda put-function-concurrency --function-name orders --reserved-concurrent-executions 50`,
        snippetLang: 'bash',
      },
      {
        priority: 'medium',
        action: 'Audit the other serverless compute services',
        detail:
          'CodeBuild projects, Glue jobs, Step Functions, App Runner services and CloudFormation stacks can all run code as a role. Their permissions are frequently broader than the Lambda roles they sit alongside.',
      },
      {
        priority: 'low',
        action: 'Give functions a VPC configuration so they cannot reach the internet directly',
        detail:
          'A function in a VPC with a NAT gateway has a controlled egress path and no direct route to the metadata service unless the endpoint is reachable. Where the function does not need the network, leave it out of the VPC entirely.',
      },
    ],
  },
  checklist: [
    {
      id: 'sls-1',
      text: 'List every function with its execution role and runtime.',
      command:
        'aws lambda list-functions --query "Functions[].[FunctionName,Role,Runtime,PackageType]" --output table',
      expected:
        'One distinct role per function, a supported runtime, and no function still on a deprecated Python or Node version.',
    },
    {
      id: 'sls-2',
      text: 'Check whether any function URL is unauthenticated.',
      command:
        'aws lambda list-functions --query "Functions[].FunctionName" --output text | xargs -I{} aws lambda get-function-url-config --function-name {}',
      expected:
        'Every function URL uses AuthType AWS_IAM. A NONE result is a public endpoint.',
    },
    {
      id: 'sls-3',
      text: 'Inspect the event source mappings and the resource policies of the queues and topics.',
      command:
        'aws lambda list-event-source-mappings --query "EventSourceMappings[].[EventSourceArn,FunctionArn]" && aws sqs list-queues',
      expected:
        'Every queue and topic that triggers a function names its allowed senders, and there are no wildcard producers.',
    },
    {
      id: 'sls-4',
      text: 'Read the environment of each function and check for embedded secrets.',
      command:
        'aws lambda list-functions --query "Functions[].FunctionName" --output text | xargs -I{} aws lambda get-function-configuration --function-name {} --query "[FunctionName,Environment.Variables]"',
      expected: 'No variable name or value looks like a key, password, token or secret.',
    },
    {
      id: 'sls-5',
      text: 'Confirm which principals are permitted to invoke each function.',
      command:
        'aws lambda list-functions --query "Functions[].FunctionName" --output text | xargs -I{} aws lambda get-policy --function-name {}',
      expected:
        'Only the API Gateway service principal and the expected principals appear. No account you do not recognise.',
    },
    {
      id: 'sls-6',
      text: 'Simulate the execution role of a function to see what an attacker would inherit.',
      command:
        'aws iam simulate-principal-policy --policy-source arn:aws:iam::123456789012:role/orders-exec --action-names lambda:CreateFunction iam:PassRole s3:GetObject --resource-arns arn:aws:s3:::app-data/orders/*',
      expected:
        'lambda:CreateFunction and iam:PassRole are denied for a normal application function.',
    },
    {
      id: 'sls-7',
      text: 'Check the API Gateway authorizers and their identity sources.',
      command:
        'aws apigatewayv2 get-apis --query "Items[].[Name,RouteSelectionExpression]" && aws apigatewayv2 get-authorizers --query "Items[].[Name,Type,IdentitySource]"',
      expected:
        'Every route that needs authorisation has an authorizer attached, and every authorizer uses JWT or IAM rather than REQUEST.',
    },
  ],
  references: [
    { label: 'AWS Lambda function URLs', url: 'https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html' },
    { label: 'AWS Lambda execution roles', url: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html' },
    { label: 'AWS SQS access policy', url: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-iam-access-control.html' },
    { label: 'AWS API Gateway authorization', url: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control.html' },
  ],
  updated: '2026-11-22',
}
