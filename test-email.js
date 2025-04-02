const nodemailer = require('nodemailer');

// Create a transporter using Gmail SMTP
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'travelexplorer923@gmail.com',
        pass: 'fgql qjjo knnl ffma'
    }
});

// Test the SMTP connection
transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP connection error:', error);
    } else {
        console.log('SMTP connection successful:', success);
    }
});

// Send a test email
const mailOptions = {
    from: 'Travel Explorer <travelexplorer923@gmail.com>',
    to: 'pateldapuj@gmail.com',
    subject: 'Test Email from Travel Explorer',
    text: 'This is a test email to verify Gmail SMTP credentials.',
    html: '<p>This is a test email to verify Gmail SMTP credentials.</p>'
};

transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
        console.error('Error sending test email:', error);
    } else {
        console.log('Test email sent:', info.response);
    }
});
