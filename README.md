# AWS Inventory
A set of checks for doing audit and inventory of AWS accounts.  

AWS Inventory is an extremely lightweight tool to do an audit of a single AWS account or 1000's of accounts in an AWS Organization.  

## Stage of the project

- [x] Early stage
- [ ] Used for a single professional audit of AWS account(s)
- [ ] Used several times for large Enterprise AWS Organizations

## Purpose
The purpose of AWS Inventory is for Cloud Engineers and Security Professionals to do a quick audit on AWS accounts. This with the only requirement of having audit access for the accounts to investigate.  

It is **not** a competitor to AWS native tools or commercial tools aimed for large Enterprises.

![aws-inventory-image](position-aws-inventory.png)

### Why AWS Inventory?
There are two important characteristics of the tool.

#### 1. Serverless executable
AWS Inventory can be cloned (this repo from GitHub) and executed directly from [AWS CloudShell][1]. No pre required installation on laptop or server is needed.

#### 2. Extendable with more checks
Although the tool is very lightweight it is also extended. It is written in Python with boto3 library for querying AWS resources. 
Makes it very suitable for Cloud Adoption Engineers that need additional compliance checks.


[1]: https://aws.amazon.com/cloudshell/