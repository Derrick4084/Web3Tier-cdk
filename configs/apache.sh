#!/bin/sh
sudo su
yum install -y httpd
systemctl enable httpd
systemctl start httpd
cd /var/www/html
mkdir Css
mkdir Scripts
touch index.html
chmod 775 index.html
echo '<!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <title>A Basic HTML5 Template</title>

        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;800&display=swap"
          rel="stylesheet"
        />
        <link rel="stylesheet" href="css/styles.css?v=1.0" />
      </head>' > index.html

echo ' <body>
        <div class="wrapper">
          <div class="container">
            <h1>Welcome! An Apache web server has been started successfully.</h1>
            <p>Replace this with your own index.html file in /var/www/html.</p>' >> index.html
            
echo '<p> EC2 Instance hostname: ' >> index.html
echo $(hostname -f) >> index.html 
echo '</p>
      <p> EC2 InstanceId: ' >> index.html
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/instance-id >> index.html             
echo ' </p>                      
          </div>
        </div>
      </body>
    </html>
    <style>
      body {
        background-color: #34333d;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: Inter;
        padding-top: 128px;
      }

      .container {
        box-sizing: border-box;
        width: 741px;
        height: 449px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: flex-start;
        padding: 48px 48px 48px 48px;
        box-shadow: 0px 1px 32px 11px rgba(38, 37, 44, 0.49);
        background-color: #5d5b6b;
        overflow: hidden;
        align-content: flex-start;
        flex-wrap: nowrap;
        gap: 24;
        border-radius: 24px;
      }

      .container h1 {
        flex-shrink: 0;
        width: 100%;
        height: auto; /* 144px */
        position: relative;
        color: #ffffff;
        line-height: 1.2;
        font-size: 40px;
      }
      .container p {
        position: relative;
        color: #ffffff;
        line-height: 1.2;
        font-size: 18px;
      }
    </style>' >> index.html