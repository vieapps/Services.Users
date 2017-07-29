#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	internal static class Global
	{

		#region Caching mechanism
		static int _CacheTime = 0;

		/// <summary>
		/// Gets the default time for caching data
		/// </summary>
		public static int CacheTime
		{
			get
			{
				if (Global._CacheTime < 1)
					try
					{
						Global._CacheTime = ConfigurationManager.AppSettings["CacheTime"].CastAs<int>();
					}
					catch
					{
						Global._CacheTime = 30;
					}
				return Global._CacheTime;
			}
		}

		static CacheManager _Cache = new CacheManager("VIEApps-Services-Users", "Sliding", Global.CacheTime);

		/// <summary>
		/// Gets the default cache storage
		/// </summary>
		public static CacheManager Cache { get { return Global._Cache; } }
		#endregion

		#region Encryption keys
		static string _AESKey = null;
		/// <summary>
		/// Geths the key for working with AES
		/// </summary>
		public static string AESKey
		{
			get
			{
				if (Global._AESKey == null)
				{
					try
					{
						Global._AESKey = ConfigurationManager.AppSettings["AESKey"];
					}
					catch
					{
						Global._AESKey = null;
					}

					if (string.IsNullOrWhiteSpace(Global._AESKey))
						Global._AESKey = "VIEApps-c98c6942-Default-0ad9-AES-40ed-Encryption-9e53-Key-65c501fcf7b3";
				}
				return Global._AESKey;
			}
		}

		public static byte[] GenerateEncryptionKey(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, false, 256);
		}

		public static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

		static string _JWTKey = null;
		/// <summary>
		/// Geths the key for working with JSON Web Token
		/// </summary>
		public static string JWTKey
		{
			get
			{
				if (Global._JWTKey == null)
				{
					try
					{
						Global._JWTKey = ConfigurationManager.AppSettings["JWTKey"];
					}
					catch
					{
						Global._JWTKey = null;
					}

					if (string.IsNullOrWhiteSpace(Global._JWTKey))
						Global._JWTKey = "VIEApps-49d8bd8c-Default-babc-JWT-43f4-Sign-bc30-Key-355b0891dc0f";
				}
				return Global._JWTKey;
			}
		}

		public static string GenerateJWTKey()
		{
			return Global.AESKey.GetHMACSHA512(Global.AESKey).ToBase64Url(false, true);
		}

		static string _RSAKey = null;
		/// <summary>
		/// Geths the key for working with RSA
		/// </summary>
		public static string RSAKey
		{
			get
			{
				if (Global._RSAKey == null)
				{
					try
					{
						Global._RSAKey = ConfigurationManager.AppSettings["RSAKey"];
					}
					catch
					{
						Global._RSAKey = null;
					}

					if (string.IsNullOrWhiteSpace(Global._RSAKey))
						Global._RSAKey = "FU4UoaKHeOYHOYDFlxlcSnsAelTHcu2o0eMAyzYwdWXQCpHZO8DRA2OLesV/JAilDRKILDjEBkTWbkghvLnlss4ymoqZzzJrpGn/cUjRP2/4P2Q18IAYYdipP65nMg4YXkyKfZC/MZfArm8pl51+FiPtQoSG0fHkmoXlq5xJ0g7jhzyMJelZjsGq+3QPji3stj89o5QK5WZZhxOmcGWvjsSLMTrV9bF4Gd9Si5UG8Wzs9/iybvu/yt3ZvIjo9kxrLceVpW/cQjDEhqQzRogpQPtSfkTgeEBtjkp91B+ISGquWWAPUt/bMjBR94zQWCBneIB6bEHY9gMDjabyZDsiSKSuKlvDWpEEx8j2DJLcqstXHs9akw5k44pusVapamk2TCSjcCnEX9SFUbyHrbb3ODJPBqVL4sAnKLl8dv54+ihvb6Oooeq+tiAx6LVwmSCTRZmGrgdURO110eewrEAbKcF+DxHe7wfkuKYLDkzskjQ44/BWzlWydxzXHAL3r59/1P/t7AtP9CAZVv9MXQghafkCJfEx+Q94gfyzl79PwCFrKa4YcEUAjif55aVaJcWdPWWBIaIgELlf/NgCzGRleTKG0KP1dcdkpbpQZb7lik6JLUWlPD0YaFpEomjpwNeblK+KElUWhqgh2SPtsDyISYB22ZsThWI4kdKHsngtR+SF7gsnuR4DUcsew99R3hFtC/9jtRxNgvVukMWy5q17gWcQQPRf4zbWgLfqe3uJwz7bitf9O5Okd+2INMb5iHKxW7uxemVfMUKKCT+60PUtsbKgd+oqOpOLhfwC2LbTE3iCOkPuKkKQAIor1+CahhZ7CWzxFaatiAVKzfSTdHna9gcfewZlahWQv4+frqWa6rfmEs8EbJt8sKimXlehY8oZf3TaHqS5j/8Pu7RLVpF7Yt3El+vdkbzEphS5P5fQdcKZCxGCWFl2WtrP+Njtw/J/ifjMuxrjppo4CxIGPurEODTTE3l+9rGQN0tm7uhjjdRiOLEK/ulXA04s5qMDfZTgZZowS1/379S1ImflGSLXGkmOjU42KsoI6v17dXXQ/MwWd7wilHC+ZRLsvZC5ts0F7pc4Qq4KmDZG4HKKf4SIiJpbpHgovKfVJdVXrTL/coHpg+FzBNvCO02TUBqJytD4dV4wZomSYwuWdo5is4xYjpOdMMZfzipEcDn0pNM7TzNonLAjUlefCAjJONl+g3s1tHdNZ6aSsLF63CpRhEchN3HFxSU4KGj0EbaR96Fo8PMwhrharF/QKWDfRvOK+2qsTqwZPqVFygObZq6RUfp6wWZwP8Tj+e1oE9DrvVMoNwhfDXtZm7d2Yc4eu+PyvJ7louy5lFGdtIuc9u3VUtw/Y0K7sRS383T+SHXBHJoLjQOK65TjeAzrYDUJF1UMV3UvuBrfVMUErMGlLzJdj/TqYDQdJS5+/ehaAnK4aDYSHCI8DQXF5NWLFlOSDy/lHIjN5msz/tfJTM70YqMQgslQmE5yH78HEQytlTsd+7WlhcLd1LpjylXQJhXYLRM8RX9zoKi7gJxNYe1GpnpQhfPpIg28trSwvs4zMPqf3YWf12HM1F7M9OUIkQoUtwyEUE5DUv2ZkDjYrMHbTN9xuJTDH/5FNsyUYCAER0Cgt/p1H+08fFFdrdZNIVRwI2s7mcMgIXtAcDLagcf0cxn1qYyc1vC9wmX7Ad/Sy69D+Yfhr2aJGgxSN1m7VIGncBfWGiVMwoaJi//pDRkmfkusAq+LypEZHy83HWf3hvpxvZBLjxRZeYXA4SMcTRMrPlkfzpGPd8Pe5JtYotUvJHJ/QRk/GqTnJuiB+hwvB7d73P+jwpE4gXpJszHHbYwQEpsdLg0xOTWDHMxF08IfLipuM7d9yTEziMfBApJ9R3+fTOMJ0h7BgCWiYp6DmNwPbmrmHbbXhwNJ2dSWS15+x/iWKEV+zz1rJTpZpqWyo4/EGg8Ao4DIXHSV8cHk4vOywsC2Kff/d7tE1jXKpWDLEo6Yo0NIgHG6gehWPSbnHWQNw6hkyKh/sO6IT0PGgM2A/FgYrsALTxbBoakMuCh+FPS/y4FXWQB80ABmKQTwql0jBAMhhBJTjdH0mS21WOj0wQ8gZgddpyePc5VPXuT9Tf6KqFwFs29f6IZDRrQs609aM/QNgfJqfhSlmzYnuDUJxzXpSzUmU9lejvu/GqO2T1XmY/ergxK9SI7aAah3TQIyZ36umMpUtsoN6hFy5RyMBnNJ/Cvt56pS5wLaq0Gl8WjctHmxAHy+UfIOh0P3HATlp2cto+w=";
				}
				return Global._RSAKey;
			}
		}

		static RSACryptoServiceProvider _RSA = null;

		internal static RSACryptoServiceProvider RSA
		{
			get
			{
				if (Global._RSA == null)
					try
					{
						Global._RSA = CryptoService.CreateRSAInstance(Global.RSAKey.Decrypt());
					}
					catch (Exception ex)
					{
						throw ex;
					}
				return Global._RSA;
			}
		}

		static string _RSAExponent = null;

		public static string RSAExponent
		{
			get
			{
				if (Global._RSAExponent == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAExponent = xmlDoc.DocumentElement.ChildNodes[1].InnerText.ToHexa(true);
				}
				return Global._RSAExponent;
			}
		}

		static string _RSAModulus = null;

		public static string RSAModulus
		{
			get
			{
				if (Global._RSAModulus == null)
				{
					var xmlDoc = new System.Xml.XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAModulus = xmlDoc.DocumentElement.ChildNodes[0].InnerText.ToHexa(true);
				}
				return Global._RSAModulus;
			}
		}
		#endregion

		#region Encrypt/Decrypt
		public static string AESEncrypt(string data, string key = null)
		{
			return data.Encrypt(string.IsNullOrWhiteSpace(key) ? Global.AESKey : key);
		}

		public static string AESDecrypt(string data, string key = null)
		{
			return data.Decrypt(string.IsNullOrWhiteSpace(key) ? Global.AESKey : key);
		}

		public static string RSAEncrypt(string data)
		{
			return CryptoService.RSAEncrypt(Global.RSA, data);
		}

		public static string RSADecrypt(string data)
		{
			return CryptoService.RSADecrypt(Global.RSA, data);
		}
		#endregion

	}

	//  --------------------------------------------------------------------------------------------

	[Serializable]
	[Repository]
	public abstract class DataAccessor<T> : RepositoryBase<T> where T : class { }
}