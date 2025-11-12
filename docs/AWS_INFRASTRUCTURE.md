# AWS Infrastructure Setup

## Architecture Overview

```
Internet Gateway
    ↓
Application Load Balancer
    ↓
ECS Fargate Service (Auto-scaling)
    ↓
RDS PostgreSQL (Multi-AZ) + ElastiCache Redis
```

## Required AWS Resources

### 1. VPC and Networking
- VPC with public and private subnets across 2 AZs
- Internet Gateway
- NAT Gateway
- Route Tables
- Security Groups

### 2. Application Load Balancer (ALB)
- Public-facing ALB
- Target Group for ECS tasks
- Health check configuration: `/health`
- SSL/TLS certificate (ACM)

### 3. ECS Cluster
- Fargate launch type
- Service with 2-10 tasks (auto-scaling)
- Task definition:
  - CPU: 512 (.5 vCPU)
  - Memory: 1024 MB (1 GB)
  - Container port: 8000

### 4. ECR Repository
- Repository name: `email-integration-service`
- Image scanning enabled
- Lifecycle policy for old images

### 5. RDS PostgreSQL
- Engine: PostgreSQL 15
- Instance: db.t3.micro (production: db.t3.medium)
- Multi-AZ deployment
- Automated backups (7 days retention)
- Encryption at rest

### 6. ElastiCache Redis
- Engine: Redis 7
- Node type: cache.t3.micro (production: cache.t3.medium)
- Multi-AZ with automatic failover
- Encryption in transit and at rest

### 7. Secrets Manager
Store sensitive configuration:
- Database credentials
- JWT secret key
- OAuth client secrets
- Redis connection string

### 8. CloudWatch
- Container logs
- Application metrics
- Alarms for:
  - High CPU usage
  - High memory usage
  - Error rates
  - Response times

### 9. IAM Roles
- ECS Task Execution Role
- ECS Task Role (with ECR, CloudWatch, Secrets Manager permissions)

## Environment Variables in ECS

```json
{
  "environment": [
    {
      "name": "ENVIRONMENT",
      "value": "production"
    }
  ],
  "secrets": [
    {
      "name": "DATABASE_URL",
      "valueFrom": "arn:aws:secretsmanager:region:account:secret:email-integration/database-url"
    },
    {
      "name": "SECRET_KEY",
      "valueFrom": "arn:aws:secretsmanager:region:account:secret:email-integration/jwt-secret"
    },
    {
      "name": "REDIS_URL",
      "valueFrom": "arn:aws:secretsmanager:region:account:secret:email-integration/redis-url"
    }
  ]
}
```

## Deployment Steps

### Initial Setup

1. **Create VPC and Networking**
   ```bash
   aws ec2 create-vpc --cidr-block 10.0.0.0/16
   ```

2. **Create RDS Instance**
   ```bash
   aws rds create-db-instance \
     --db-instance-identifier email-integration-db \
     --db-instance-class db.t3.micro \
     --engine postgres \
     --master-username admin \
     --master-user-password <password> \
     --allocated-storage 20
   ```

3. **Create ElastiCache Cluster**
   ```bash
   aws elasticache create-cache-cluster \
     --cache-cluster-id email-integration-redis \
     --cache-node-type cache.t3.micro \
     --engine redis \
     --num-cache-nodes 1
   ```

4. **Create ECR Repository**
   ```bash
   aws ecr create-repository \
     --repository-name email-integration-service \
     --region us-east-1
   ```

5. **Create ECS Cluster**
   ```bash
   aws ecs create-cluster \
     --cluster-name email-integration-cluster
   ```

6. **Register Task Definition**
   ```bash
   aws ecs register-task-definition \
     --cli-input-json file://task-definition.json
   ```

7. **Create ECS Service**
   ```bash
   aws ecs create-service \
     --cluster email-integration-cluster \
     --service-name email-integration-service \
     --task-definition email-integration-task \
     --desired-count 2 \
     --launch-type FARGATE \
     --load-balancers targetGroupArn=<arn>,containerName=app,containerPort=8000
   ```

## Auto-scaling Configuration

### Target Tracking Scaling Policy

```json
{
  "targetValue": 70.0,
  "predefinedMetricSpecification": {
    "predefinedMetricType": "ECSServiceAverageCPUUtilization"
  },
  "scaleInCooldown": 300,
  "scaleOutCooldown": 60
}
```

## Security Best Practices

1. **Network Security**
   - Place RDS and Redis in private subnets
   - Use security groups to restrict access
   - Enable VPC flow logs

2. **Data Protection**
   - Enable encryption at rest for RDS and Redis
   - Enable encryption in transit (TLS/SSL)
   - Use AWS Secrets Manager for sensitive data

3. **Access Control**
   - Use IAM roles instead of access keys
   - Follow principle of least privilege
   - Enable MFA for AWS Console access

4. **Monitoring**
   - Enable CloudWatch Container Insights
   - Set up CloudWatch alarms
   - Use AWS X-Ray for distributed tracing

## Cost Optimization

- Use Auto Scaling to match demand
- Use Reserved Instances for predictable workloads
- Implement lifecycle policies for ECR images
- Use CloudWatch Logs retention policies
- Monitor with AWS Cost Explorer

## Disaster Recovery

- RDS automated backups (7-day retention)
- RDS automated snapshots
- Multi-AZ deployment for high availability
- Cross-region replication for RDS (optional)
- Regular testing of backup restoration

## Maintenance Windows

- RDS: Sunday 03:00-04:00 UTC
- ElastiCache: Sunday 04:00-05:00 UTC
- ECS rolling updates: Zero downtime deployments
