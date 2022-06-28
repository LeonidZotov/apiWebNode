const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  const transporter = nodemailer.createTransport({
    host: 'smtp.mailtrap.io',
    port: 2525,
    auth: {
      user: 'b2b1735bda795d',
      pass: 'ea992ba7d7e64f',
    },
    tls: {
      rejectUnauthorized: false,
    },
  });
  const mailOptions = {
    from: 'Lenid <somemail@gmail.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
  };
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
