import enum


class DataSourceType(str, enum.Enum):
    CLOUDTRAIL = "cloudtrail"
    VPC_FLOW_LOGS = "vpc_flow_logs"
    CLOUDWATCH = "cloudwatch"
    GUARDDUTY = "guardduty"
    CONFIG = "config"
    S3 = "s3"
    EC2 = "ec2"
    IAM = "iam"
    OTHER = "other"