import aws_cdk as core
import aws_cdk.assertions as assertions

from web_3tier.web_3tier_stack import Web3TierStack

# example tests. To run these tests, uncomment this file along with the example
# resource in web_3tier/web_3tier_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = Web3TierStack(app, "web-3tier")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
