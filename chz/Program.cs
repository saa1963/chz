using CryptoPro.Sharpei;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace chz
{
    class Program
    {
        static HttpClient httpClient;
        [STAThread]
        static async Task Main(string[] args)
        {
            WebRequestHandler handler = new WebRequestHandler();
            httpClient = new HttpClient(handler);
            httpClient.BaseAddress = new Uri("https://int01.gismt.crpt.tech/api/v3/true-api/");
            httpClient.DefaultRequestHeaders.Accept.Clear();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml"));

            try
            {
                if (!await AuthenticateMeAsync()) return;
                Console.WriteLine("Успешная аутентификация.");
            }
            catch(Exception ex)
            {

            }
            Console.ReadKey();
        }
        private static async Task<bool> AuthenticateMeAsync()
        {
            string uuid = null, data = null;

            var response = await httpClient.GetAsync("auth/key");
            using (var stream = await response.Content.ReadAsStreamAsync())
            {
                using (var xr = XmlReader.Create(stream))
                {
                    while (xr.Read())
                    {
                        if (xr.NodeType == XmlNodeType.Element)
                        {
                            if (xr.Name == "uuid") uuid = xr.ReadElementContentAsString();
                            if (xr.Name == "data") data = xr.ReadElementContentAsString();
                        }
                    }
                }
            }
            if (uuid == null || data == null) {
                Console.WriteLine("Запрос auth/key не возвратил данные");
                return false;
            }
            string signedData = SignData(data);
            if (signedData == null)
            {
                Console.WriteLine("Не удалось подписать данные для аутентификации");
                return false;
            }
            Console.WriteLine(signedData);
            return true;
        }

        private static string SignData(string data)
        {
            var cert = GetMyX509Certificate();
            // String msg, X509Certificate2 cert 
            using (var gost = new Gost3411CryptoServiceProvider())
            {
                var sign = new GostSignatureFormatter(cert.PrivateKey);
                var buff = Encoding.UTF8.GetBytes(data);
                var hash = gost.ComputeHash(buff);
                return Convert.ToBase64String(sign.CreateSignature(hash));
            }

        }

        private static X509Certificate2 GetMyX509Certificate()
        {
            // Открываем хранилище My.
            X509Store storeMy = new X509Store(StoreName.My,
                StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.ReadOnly);
           // Ищем сертификат клиента.
           X509Certificate2Collection certColl =
                storeMy.Certificates.Find(X509FindType.FindBySubjectName,
                "husqvarnatest", false);
            Console.WriteLine(
                "Найдено {0} сертификат(ов) в хранилище {1}",
                certColl.Count, storeMy.Name);

            // Проверяем, что нашли хотя бы один сертификат
            if (certColl.Count == 0)
            {
                Console.WriteLine(
                    "Сертификат для данного примера не найден " +
                    "в хранилище. Выберите другой сертификат. ");
                return null;
            }
            else
                return certColl[0];
        }
    }
}
