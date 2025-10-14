import Mailgen from "mailgen";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

// 1. Setup Mailgen
const mailGenerator = new Mailgen({
    theme: "default", 
    product: {
        name: "ProdManage",
        link: process.env.HOST_URL,
        logo: '/images/logo.png'
    }
});

// 2. Setup Nodemailer Transporter
const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD
    }
});

// 3. Send email function
export const sendEmail = async ({email, subject, mailContent}) => {
    // Generate the HTML email with Mailgen
    const emailBody = mailGenerator.generate(mailContent);
    const emailText = mailGenerator.generatePlaintext(mailContent);

    const mailOptions = {
        from: process.env.MAIL_USERNAME,
        to:email,
        subject,
        html: emailBody,
        text: emailText
    };

    await transporter.sendMail(mailOptions);
};

// 4. Mail templates
export const emailVerificationMailContent = (username, verificationUrl) => ({
    body: {
        name: username,
        intro: "Welcome to ProdManage! We're very excited to have you on board.",
        action: {
            instructions: "To get started with ProdManage, please click here:",
            button: {
                color: "#22BC66",
                text: "Confirm your account",
                link: verificationUrl
            }
        },
        outro: "Need help, or have questions? Just reply to this email, we'd love to help."
    }
});

export const passwordResetMailContent = (username, verificationUrl) => ({
    body: {
        name: username,
        intro: "You have received this email because a password reset request for your account was received.",
        action: {
            instructions: "Click the button below to reset your password:",
            button: {
                color: "#DC4D2F",
                text: "Reset your password",
                link: verificationUrl
            }
        },
        outro: "If you did not request a password reset, please ignore this email or reply to let us know. This link is only valid for the next 2 hours."
    }
}); 
