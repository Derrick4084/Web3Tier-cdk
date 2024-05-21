from aws_cdk import (
    Aws,
    Stack,
    CfnOutput,
    CfnTag,
    Duration,
    Fn,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
    aws_iam as _iam,
    aws_logs as logs,
    Tags,
    aws_ssm as ssm
      
)
from constructs import Construct
import base64


environment_tag = "Dev"
image_id = "ami-0df435f331839b2d6"

def create_endpoint_sb(scope: Construct, vpc: ec2.CfnVPC, group_name: str) -> ec2.CfnSecurityGroup:
    
    cidr_block = Fn.cidr(ip_block=vpc.attr_cidr_block, count=256, size_mask='8')

    sg = ec2.CfnSecurityGroup(
        scope=scope,
        id=f"sg-{group_name}",
        group_name=f"{group_name}-sg",
        group_description="Security group for interface endpoints",
        vpc_id=vpc.attr_vpc_id,
        security_group_ingress=[
            ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, cidr_ip=Fn.select(2,cidr_block)),
            ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, cidr_ip=Fn.select(3,cidr_block)),
            ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, cidr_ip=Fn.select(4,cidr_block)),
            ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, cidr_ip=Fn.select(5,cidr_block)),
            ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, cidr_ip=Fn.select(6,cidr_block)),
            ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, cidr_ip=Fn.select(7,cidr_block))
        ],

        tags=[CfnTag(key="Name", value=f"{scope.stack_name}-endpoints-sg"),
              CfnTag(key="createdBy", value=f"{scope.stack_name}"),
              CfnTag(key="Environment", value=environment_tag)])
    
    return sg

def b64_encode(filepath: str) -> str:
    with open(filepath, 'r') as f:
      data = f.read()
      string_bytes = data.encode("ascii")
      base64_bytes = base64.b64encode(string_bytes)
    return base64_bytes.decode("ascii")

class Web3TierStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        
        self.vpc_cfn = ec2.CfnVPC(
             self, "VPC",
             cidr_block="10.10.0.0/16",
             enable_dns_hostnames=True,
             enable_dns_support=True,
             tags=[CfnTag(key="Name", value=f"{self.stack_name}-vpc"),
                   CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                   CfnTag(key="Environment", value=environment_tag)]
            )
        
        self.vpcflowloggroup = logs.CfnLogGroup(
            self, 
            "vpcflowloggroup",
            log_group_name=f"/{self.stack_name}/vpcflowlogs",
            retention_in_days=14,
        )
        self.vpcflowloggroup.apply_removal_policy(RemovalPolicy.DESTROY)

        self.vpcflowlogrole = _iam.Role(self, "vpcflowlogsrole",
                assumed_by=_iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
                path="/"
        )
        self.vpcflowlogrole.attach_inline_policy(
            _iam.Policy(
                self, 
                "vpcflowlogspolicy",
                policy_name="VpcFlowLogsPolicy",
                statements=[_iam.PolicyStatement(
                    effect=_iam.Effect.ALLOW,
                    actions=["logs:CreateLogGroup", 
                             "logs:CreateLogStream", 
                             "logs:PutLogEvents",
                             "logs:DescribeLogGroups",
                             "logs:DescribeLogStreams",
                             "logs:DeleteLogGroup",
                             "logs:DeleteLogStream"
                            ],
                    resources=[f"arn:aws:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:log-group:/{self.stack_name}/vpcflowlogs*"]
                   )
                ]
            )
        )

        self.flowlogs = ec2.CfnFlowLog(
            self, "vpcflowlogs",
            resource_id=self.vpc_cfn.attr_vpc_id,
            resource_type="VPC",
            traffic_type="ALL",
            log_destination_type="cloud-watch-logs",
            log_destination=self.vpcflowloggroup.attr_arn,
            deliver_logs_permission_arn=self.vpcflowlogrole.role_arn
        )
        self.flowlogs.add_dependency(self.vpcflowloggroup)
        self.flowlogs.apply_removal_policy(RemovalPolicy.DESTROY)

        self.pubicsubnet1 = ec2.CfnSubnet(
            self, 
            "sub-igw-ngw0",
            cidr_block="10.10.1.0/27",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(0, Fn.get_azs(region=f"{Aws.REGION}")),
            map_public_ip_on_launch=True,
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-sub-igw-ngw0"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        self.pubicsubnet2 = ec2.CfnSubnet(
            self, 
            "sub-igw-ngw1",
            cidr_block="10.10.2.0/27",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(1, Fn.get_azs(region=f"{Aws.REGION}")),
            map_public_ip_on_launch=True,
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-sub-igw-ngw1"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        
        self.websubnet1 = ec2.CfnSubnet(
            self, 
            "sub-web1",
            cidr_block="10.10.3.0/24",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(0, Fn.get_azs(region=f"{Aws.REGION}")),
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-websubnet1"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        
        self.websubnet2 = ec2.CfnSubnet(
            self, 
            "sub-web2",
            cidr_block="10.10.4.0/24",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(1, Fn.get_azs(region=f"{Aws.REGION}")),
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-websubnet2"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        

        self.appsubnet1 = ec2.CfnSubnet(
            self, 
            "sub-app1",
            cidr_block="10.10.5.0/24",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(0, Fn.get_azs(region=f"{Aws.REGION}")),
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-appsubnet1"),
                  CfnTag(key="created-by", value=f"{self.stack_name}"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        
        self.appsubnet2 = ec2.CfnSubnet(
            self, 
            "sub-app2",
            cidr_block="10.10.6.0/24",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(1, Fn.get_azs(region=f"{Aws.REGION}")),
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-appsubnet2"),
                  CfnTag(key="created-by", value=f"{self.stack_name}"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        

        self.datasubnet1 = ec2.CfnSubnet(
            self, 
            "sub-data1",
            cidr_block="10.10.7.0/27",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(0, Fn.get_azs(region=f"{Aws.REGION}")),
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-datasubnet1"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        
        self.datasubnet2 = ec2.CfnSubnet(
            self, 
            "sub-data2",
            cidr_block="10.10.8.0/27",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            availability_zone=Fn.select(1, Fn.get_azs(region=f"{Aws.REGION}")),
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-datasubnet2"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        
        # Elastic IP interfaces for az0 and az1 natgateways
        self.NGWEIPaz0 = ec2.CfnEIP(
            self,
            "eip-az0",
            domain="vpc",
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-ngw-eip"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)])       
        self.NGWEIPaz1 = ec2.CfnEIP(
            self,
            "eip-az1",
            domain="vpc",
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-ngw-eip"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)])
        

        # Natgateways for public subnets in az0 and az1  
        self.NGWaz0 = ec2.CfnNatGateway(
            self,
            "ngw-az0",
            allocation_id=self.NGWEIPaz0.attr_allocation_id,
            subnet_id=self.pubicsubnet1.attr_subnet_id,
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-az0-ngw"),
                  CfnTag(key="created-by", value=f"{self.stack_name}"),
                  CfnTag(key="Environment", value=environment_tag)]
            )       
        self.NGWaz1 = ec2.CfnNatGateway(
            self,
            "ngw-az1",
            allocation_id=self.NGWEIPaz1.attr_allocation_id,
            subnet_id=self.pubicsubnet2.attr_subnet_id,
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-az1-ngw"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
            )
        
        # Internet gateway with vpc attachment
        self.cfn_internet_gateway = ec2.CfnInternetGateway(
            self, 
            "igw",
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-igw"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
           )
        self.cfn_internet_gateway.add_dependency(self.vpc_cfn)

        self.igw_attachment = ec2.CfnVPCGatewayAttachment(
            self,
            "igw-attach",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            internet_gateway_id=self.cfn_internet_gateway.attr_internet_gateway_id
        )

        # Public subnets route to the internet
        self.InternetRouteTable = ec2.CfnRouteTable(
            self,
            "igw-rtb",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-igw-rtb"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
                  )
        self.igw_route = ec2.CfnRoute(
            self,
            "igw-route",
            destination_cidr_block="0.0.0.0/0",
            route_table_id=self.InternetRouteTable.attr_route_table_id,
            gateway_id=self.cfn_internet_gateway.attr_internet_gateway_id
            )
        self.pub1_route_association = ec2.CfnSubnetRouteTableAssociation(
            self,
            "igw-pub1-rta",
            route_table_id=self.InternetRouteTable.attr_route_table_id,
            subnet_id=self.pubicsubnet1.attr_subnet_id
        )
        self.pub2_route_association = ec2.CfnSubnetRouteTableAssociation(
            self,
            "igw-pub2-rta",
            route_table_id=self.InternetRouteTable.attr_route_table_id,
            subnet_id=self.pubicsubnet2.attr_subnet_id     
        )

        # Shared route table and routes to natgateway for az0 subnets
        self.Az0SharedRouteTable = ec2.CfnRouteTable(
            self,
            "az0shared-rtb",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-az0-shared-rtb"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
                  )
        ec2.CfnRoute(
            self,
            "az0shared-rt",
            destination_cidr_block="0.0.0.0/0",
            route_table_id=self.Az0SharedRouteTable.attr_route_table_id,
            nat_gateway_id=self.NGWaz0.attr_nat_gateway_id
            )
        
        # Shared route table and routes to natgateway for az1 subnets
        self.Az1SharedRouteTable = ec2.CfnRouteTable(
            self,
            "az1shared-rtb",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-az1-shared-rtb"),
                  CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                  CfnTag(key="Environment", value=environment_tag)]
                  )
        ec2.CfnRoute(
            self,
            "az1shared-rt",
            destination_cidr_block="0.0.0.0/0",
            route_table_id=self.Az1SharedRouteTable.attr_route_table_id,
            nat_gateway_id=self.NGWaz1.attr_nat_gateway_id
            )
        
        # Subnet route table associations   
        WebSubnet1RouteTableAssociation = ec2.CfnSubnetRouteTableAssociation(
            self,
            "websub1-rta",
            route_table_id=self.Az0SharedRouteTable.attr_route_table_id,
            subnet_id=self.websubnet1.attr_subnet_id
        )
        WebSubnet2RouteTableAssociation = ec2.CfnSubnetRouteTableAssociation(
            self,
            "websub2-rta",
            route_table_id=self.Az1SharedRouteTable.attr_route_table_id,
            subnet_id=self.websubnet2.attr_subnet_id   
        )
        AppSubnet1RouteTableAssociation = ec2.CfnSubnetRouteTableAssociation(
            self,
            "appsub1-rta",
            route_table_id=self.Az0SharedRouteTable.attr_route_table_id,
            subnet_id=self.appsubnet1.attr_subnet_id
        )
        AppSubnet2RouteTableAssociation = ec2.CfnSubnetRouteTableAssociation(
            self,
            "appsub2-rta",
            route_table_id=self.Az1SharedRouteTable.attr_route_table_id,
            subnet_id=self.appsubnet2.attr_subnet_id
        )
        DataSubnet1RouteTableAssociation = ec2.CfnSubnetRouteTableAssociation(
            self,
            "datasub1-rta",
            route_table_id=self.Az0SharedRouteTable.attr_route_table_id,
            subnet_id=self.datasubnet1.attr_subnet_id         
        )
        DataSubnet2RouteTableAssociation = ec2.CfnSubnetRouteTableAssociation(
            self,
            "datasub2-rta",
            route_table_id=self.Az1SharedRouteTable.attr_route_table_id,
            subnet_id=self.datasubnet2.attr_subnet_id         
        )

        # s3 and dynamodb gateway endpoints        
        s3_endpoint = ec2.CfnVPCEndpoint(
            self,
            "endpt-gw-s3",
            vpc_endpoint_type="Gateway",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            service_name=f"com.amazonaws.{self.region}.s3",
            route_table_ids=[self.Az0SharedRouteTable.attr_route_table_id, self.Az1SharedRouteTable.attr_route_table_id]
            )   
        dynamodb_endpoint  = ec2.CfnVPCEndpoint(
            self,
            "endpt-gw-dynamodb",
            vpc_endpoint_type="Gateway",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            service_name=f"com.amazonaws.{self.region}.dynamodb",
            route_table_ids=[self.Az0SharedRouteTable.attr_route_table_id, self.Az1SharedRouteTable.attr_route_table_id]
            )
        
        # inteface endpoint shared security group and endpoint creation
        self.interface_endpoint_sg = create_endpoint_sb(self, self.vpc_cfn, "endpoints")

        self.vpc_interface_endpoints = {         
            'ec2': f"com.amazonaws.{self.region}.ec2",
            'ec2-messages': f"com.amazonaws.{self.region}.ec2messages",
            'ssm': f"com.amazonaws.{self.region}.ssm",
            'ssm-messages': f"com.amazonaws.{self.region}.ssmmessages",
            # 'autoscaling': ec2.InterfaceVpcEndpointAwsService('autoscaling'),
            'cloudformation': f"com.amazonaws.{self.region}.cloudformation",
            'cloudwatch-logs': f"com.amazonaws.{self.region}.logs",
            'cloudwatch-monitoring': f"com.amazonaws.{self.region}.monitoring",
        }

        for name, interface_service in self.vpc_interface_endpoints.items():
            ec2.CfnVPCEndpoint(
              self,
              f"endpt-{name}",
              vpc_endpoint_type="Interface",
              vpc_id=self.vpc_cfn.attr_vpc_id,
              private_dns_enabled=True,
              service_name=interface_service,
              subnet_ids=[self.websubnet1.attr_subnet_id, self.websubnet2.attr_subnet_id],
              security_group_ids=[self.interface_endpoint_sg.attr_group_id]   
           )
            
        parameters = {         
            'VPC': self.vpc_cfn.attr_vpc_id,
            'PublicSub1': self.pubicsubnet1.attr_subnet_id,
            'PublicSub2': self.pubicsubnet2.attr_subnet_id,
            'WebSub1': self.websubnet1.attr_subnet_id,
            'WebSub2': self.websubnet2.attr_subnet_id,
        }
        for name, param in parameters.items():
            str_param = ssm.StringParameter(
                self,
                f"{name}-param",
                parameter_name=f"/{self.stack_name}/{name}",
                # string_value=cast(str, param),
                string_value=str(param),
                tier=ssm.ParameterTier.STANDARD,
            )
            str_param.apply_removal_policy(RemovalPolicy.DESTROY)


        self.ec2instancerole = _iam.Role(
            self, 
            "ec2-instance-role",
            assumed_by=_iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[_iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
                              _iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMDirectoryServiceAccess"),
                              _iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy"),
                              _iam.ManagedPolicy.from_managed_policy_arn(
                                  self,
                                  "S3Access",
                                  f"arn:aws:iam::{self.account}:policy/SSMInstanceProfileS3Policy"
                              )],
            path="/",
            role_name=f"{self.stack_name}InstanceProfile"
        )
        self.ec2instanceprofile = _iam.InstanceProfile(
            self,
            "ec2-instance-profile",
            instance_profile_name=f"{self.stack_name}Ec2InstanceProfile",
            path="/",
            role=self.ec2instancerole
            )
        
        self.alb_security_group = ec2.CfnSecurityGroup(
          self,
          "alb-sg",
          group_name=f"{self.stack_name}-alb-sg",
          group_description="Security group for ALB",
          vpc_id=self.vpc_cfn.attr_vpc_id,
          security_group_ingress=[
              ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=80, to_port=80, cidr_ip="0.0.0.0/0"),
              ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, cidr_ip="0.0.0.0/0")
            ],
          tags=[CfnTag(key="Name", value=f"{self.stack_name}-sg"),
                CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                CfnTag(key="Environment", value=environment_tag)])
        
        self.web_ec2_instance_sg = ec2.CfnSecurityGroup(
            self,
            "ec2-webinstance-sg",
            group_name=f"{self.stack_name}-web-instance-sg",
            group_description="Security group for web instance",
            vpc_id=self.vpc_cfn.attr_vpc_id,
            security_group_ingress=[
                ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=80, to_port=80, source_security_group_id=self.alb_security_group.attr_group_id),
                ec2.CfnSecurityGroup.IngressProperty(ip_protocol="tcp", from_port=443, to_port=443, source_security_group_id=self.alb_security_group.attr_group_id)
                ],
                tags=[CfnTag(key="Name", value=f"{self.stack_name}-ec2Instance-sg"),
                      CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                      CfnTag(key="Environment", value=environment_tag)])
        
        self.alb_target_group = elbv2.CfnTargetGroup(
            self,
            "alb-tg",
            health_check_path="/",
            health_check_interval_seconds=30,
            health_check_port="traffic-port",
            health_check_protocol="HTTP",
            health_check_timeout_seconds=5,
            healthy_threshold_count=5,
            name=f"{self.stack_name}-tg",
            port=80,
            protocol="HTTP",
            target_type="instance",
            target_group_attributes=[
                elbv2.CfnTargetGroup.TargetGroupAttributeProperty(
                    key="deregistration_delay.timeout_seconds", 
                    value="10")
            ],
            unhealthy_threshold_count=2,
            vpc_id=self.vpc_cfn.attr_vpc_id                 
        )

        self.alb = elbv2.CfnLoadBalancer(
            self,
            "alb",
            ip_address_type="ipv4",
            name=f"{self.stack_name}-alb",
            security_groups=[self.alb_security_group.attr_group_id],
            subnets=[self.pubicsubnet1.attr_subnet_id, self.pubicsubnet2.attr_subnet_id],
            scheme="internet-facing",
            type="application",
            tags=[CfnTag(key="Name", value=f"{self.stack_name}-alb"),
                      CfnTag(key="created-by", value=f"{self.stack_name}-stack"),
                      CfnTag(key="Environment", value=environment_tag)]
        )

        self.alb_listener = elbv2.CfnListener(
            self,
            "alb-listener",
            default_actions=[elbv2.CfnListener.ActionProperty(
                target_group_arn=self.alb_target_group.attr_target_group_arn, type="forward"
                )],
            load_balancer_arn=self.alb.attr_load_balancer_arn,
            port=80,
            protocol="HTTP"
        )
        self.alb_listener.add_dependency(self.alb)

        self.launch_template = autoscaling.CfnLaunchConfiguration(
            self,
            "asg-ec2-template",
            image_id=image_id,
            instance_type="t2.micro",
            iam_instance_profile=self.ec2instanceprofile.instance_profile_arn,
            security_groups=[self.web_ec2_instance_sg.attr_group_id],
            user_data=b64_encode("./configs/apache.sh")
        )

        self.cfn_auto_scaling_group = autoscaling.CfnAutoScalingGroup(
            self,
            "asg",
            auto_scaling_group_name=f"{self.stack_name}-asg",
            launch_configuration_name=self.launch_template.ref,
            target_group_arns=[self.alb_target_group.attr_target_group_arn],
            desired_capacity="2",
            max_size="4",
            min_size="2",
            vpc_zone_identifier=[self.websubnet1.attr_subnet_id, self.websubnet2.attr_subnet_id],
            tags=[autoscaling.CfnAutoScalingGroup.TagPropertyProperty(
                    key="Name",
                    propagate_at_launch=False,
                    value="WebServer")]
        )
        self.cfn_auto_scaling_group.add_dependency(self.alb)

        self.as_requestcount_pol = autoscaling.CfnScalingPolicy(
            self,
            "alb-request-count-pol",
            policy_type="TargetTrackingScaling",
            auto_scaling_group_name=self.cfn_auto_scaling_group.auto_scaling_group_name,
            target_tracking_configuration=autoscaling.CfnScalingPolicy.TargetTrackingConfigurationProperty(
                target_value=100,
                predefined_metric_specification=autoscaling.CfnScalingPolicy.PredefinedMetricSpecificationProperty(
                    predefined_metric_type="ALBRequestCountPerTarget",
                    resource_label=f"{self.alb.attr_load_balancer_full_name}/{self.alb_target_group.attr_target_group_full_name}"
                )
              )
        )
        self.as_requestcount_pol.add_dependency(self.cfn_auto_scaling_group)

        self.as_cpu_utilization_policy = autoscaling.CfnScalingPolicy(
            self,
            "alb-cpu-utilization-pol",
            policy_type="TargetTrackingScaling",
            auto_scaling_group_name=self.cfn_auto_scaling_group.auto_scaling_group_name,
            target_tracking_configuration=autoscaling.CfnScalingPolicy.TargetTrackingConfigurationProperty(
                target_value=70,
                predefined_metric_specification=autoscaling.CfnScalingPolicy.PredefinedMetricSpecificationProperty(
                    predefined_metric_type="ASGAverageCPUUtilization"
                )
              )
           )
        self.as_cpu_utilization_policy.add_dependency(self.cfn_auto_scaling_group)


        CfnOutput(self, "elb_dns_name", value="http://"+self.alb.attr_dns_name)
