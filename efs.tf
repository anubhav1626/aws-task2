provider "aws" {
  region   = "ap-south-1"
  profile  = "anubhav"
}

resource "tls_private_key" task_key  {
  algorithm = "RSA"
}

resource "aws_key_pair" "task2-key" {
  key_name    = "task2-key"
  public_key = tls_private_key.task_key.public_key_openssh
  }


resource "aws_vpc" "myvpc" {
  cidr_block = "10.5.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "myvpc"
  }
}

resource "aws_subnet" "mysubnet" {
  vpc_id            = "${aws_vpc.myvpc.id}"
  availability_zone = "ap-south-1a"
  cidr_block        = "10.5.1.0/24"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "mysubnet"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.myvpc.id}"
  tags = {
    Name = "gateway"
  }
}
resource "aws_route_table" "rtable" {
  vpc_id = "${aws_vpc.myvpc.id}"
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.gw.id}"
  }
  tags = {
    Name = "routetable"
  }
}
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.mysubnet.id
  route_table_id = aws_route_table.rtable.id
}

resource "aws_security_group" "allow_http" {
  name        = "allow_http"
  description = "Allow HTTP inbound traffic"
  vpc_id      = "${aws_vpc.myvpc.id}"

  ingress {
    description = "Http from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  ingress {
    description = "NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sgroup"
  }
}


resource "aws_efs_file_system" "myefs" {
  creation_token = "my-secure-efs"
  tags = {
    Name = "myefs"
  }
}

resource "aws_efs_file_system_policy" "policy" {
  file_system_id = "${aws_efs_file_system.myefs.id}"
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "efs-policy-wizard-c45881c9-af16-441d-aa48-0fbd68ffaf79",
    "Statement": [
        {
            "Sid": "efs-statement-17ef0663-52c3-4d2b-8620-d9234cbaf888",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Resource": "${aws_efs_file_system.myefs.arn}",
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "true"
                }
            }
        }
    ]
}
POLICY
}


resource "aws_efs_mount_target" "efs-mount" {
  file_system_id = "${aws_efs_file_system.myefs.id}"
  subnet_id      = "${aws_subnet.mysubnet.id}"
  security_groups = [ "${aws_security_group.allow_http.id}" ]
}


resource "aws_instance" "myweb" {
  ami           = "ami-00b494a3f139ba61f"
  instance_type = "t2.micro"
  associate_public_ip_address = true
  key_name      = "task2-key"
  availability_zone = "ap-south-1a"
  subnet_id     = "${aws_subnet.mysubnet.id}"
  security_groups = [ "${aws_security_group.allow_http.id}" ]
  tags = {
    Name = "myweb"
  }
}


resource "null_resource" "null_vol_attach"  {
  depends_on = [
    aws_efs_mount_target.efs-mount,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  tls_private_key.task_key.private_key_pem
    host     = aws_instance.myweb.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sleep 30",
      "sudo yum install -y httpd git php amazon-efs-utils nfs-utils",
      "sudo systemctl start httpd",
      "sudo systemctl enable httpd",
      "sudo chmod ugo+rw /etc/fstab",
      "sudo echo '${aws_efs_file_system.myefs.id}:/ /var/www/html efs tls,_netdev' >> /etc/fstab",
      "sudo mount -a -t efs,nfs4 defaults",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/anubhav1626/aws-task2.git  /var/www/html/"
    ]
  }
}

// Provides a S3 bucket resource & pull image to bucket from GitHub repo

resource "aws_s3_bucket" "my-bucket-9897" {
  bucket = "my-bucket-9897"
  acl    = "public-read"
  force_destroy  = true
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://my-bucket-9897"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }


depends_on = [
   null_resource.null_vol_attach,
  ]
}

resource "aws_s3_bucket_object" "object" {
  key = "anubhav.jpg"
  bucket = aws_s3_bucket.my-bucket-9897.id
  source = "anubhav.jpg"
  acl="public-read"
}


# Create Cloudfront distribution
resource "aws_cloudfront_distribution" "distribution" {
    origin {
        domain_name = "${aws_s3_bucket.my-bucket-9897.bucket_regional_domain_name}"
        origin_id = "S3-${aws_s3_bucket.my-bucket-9897.bucket}"

        custom_origin_config {
            http_port = 80
            https_port = 443
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        }
}

    # By default, show index.html file
    default_root_object = "anubhav.jpg"
    enabled = true

    # If there is a 404, return anubhav.jpg with a HTTP 200 Response
    custom_error_response {
        error_caching_min_ttl = 3000
        error_code = 404
        response_code = 200
        response_page_path = "/anubhav.jpg"
    }

    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "S3-${aws_s3_bucket.my-bucket-9897.bucket}"

        #Not Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
	    cookies {
		forward = "none"
	    }
            
        }

        viewer_protocol_policy = "redirect-to-https"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }

    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }

    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
}
resource "null_resource" "update_pic_url"  {
  depends_on = [
    null_resource.null_vol_attach,
    aws_cloudfront_distribution.distribution,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  tls_private_key.task_key.private_key_pem
    host     = aws_instance.myweb.public_ip
  }
  provisioner "remote-exec" {
    inline = [
        "sudo chmod ugo+rw /var/www/html/index.php",
        "sudo echo '<img src=http://${aws_cloudfront_distribution.distribution.domain_name}/anubhav.jpg alt='ANUBHAV PAHWA' width='500' height='600'</a>' >> /var/www/html/index.php"
    ]
  }
}


resource "null_resource" "save_key_pair"  {
	provisioner "local-exec" {
	    command = "echo  '${tls_private_key.task_key.private_key_pem}' > key.pem"
  	}
}

