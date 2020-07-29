using System;
using System.Configuration;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace OutlookSignedCardTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string command = String.Empty;

            var file = File.ReadAllBytes("cert.pfx");
            var x509 = new X509Certificate2();
            x509.Import(file, GetSettings("CertPassword"), X509KeyStorageFlags.Exportable);

            var subject = GetSubject();

            while (command != "exit")
            {
                if (command == "sendrsa")
                {
                    var privateKey = x509.PrivateKey.ToXmlString(true);
                    var rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(privateKey);

                    var rsaKey = new RsaSecurityKey(rsa);
                    var signedCard = Signer.Sign(rsaKey, subject);
                    var signedCardPayload = signedCard.RawData;

                    await Send(GetMailBody(signedCardPayload));

                    Console.WriteLine("Mail sent with RSA signed card!");

                }
                else if(command == "sendcert")
                {
                    var signedCard = Signer.Sign(x509, subject);
                    var signedCardPayload = signedCard.RawData;

                    await Send(GetMailBody(signedCardPayload));

                    Console.WriteLine("Mail sent with x509 signed card!");
                }
                command = Console.ReadLine();
            }
        }

        static string GetCard()
        {
            string adaptiveCardRawJson = File.ReadAllText("card.json");
            string minifiedCard = JsonConvert.SerializeObject(JsonConvert.DeserializeObject(adaptiveCardRawJson));

            return minifiedCard;
        }

        static Claim[] GetSubject()
        {
            // The Actionable Message provider ID generated during provider registration
            string originator = GetSettings("Originator");

            // Recipients of the email
            string[] recipients = { GetSettings("Receiver") };

            // Sender of the email
            string sender = GetSettings("Sender");

            return new Claim[]
            {
                new Claim("sender", sender),
                new Claim("originator", originator),
                new Claim("recipientsSerialized", JsonConvert.SerializeObject(recipients)),
                new Claim("adaptiveCardSerialized", GetCard())
            };
        }

        static string GetMailBody(string signedCardPayload)
        {
            string emailBody = File.ReadAllText("mail-template.html");
            return emailBody.Replace("{{signedCardPayload}}", signedCardPayload);
        }

        static async Task Send(string mailBody)
        {
            var apiKey = GetSettings("SendGridApiKey");
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress(GetSettings("Sender"));
            var subject = "Signed Card Test";
            var to = new EmailAddress(GetSettings("Receiver"));
            var plainTextContent = "Plain text";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, mailBody);
            await client.SendEmailAsync(msg);
        }

        static string GetSettings(string key)
        {
            var settingsReader = new AppSettingsReader();
            return (string) settingsReader.GetValue(key, typeof(string));
        }
    }
}
