#region Related components
using System;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Converters;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Users
{
	/// <summary>
	/// Available gender of an user's account profile
	/// </summary>
	public enum Gender
	{
		/// <summary>
		/// Don't want to provide
		/// </summary>
		NotProvided,

		/// <summary>
		/// Male
		/// </summary>
		Male,

		/// <summary>
		/// Femal
		/// </summary>
		Female
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available type of an user's account
	/// </summary>
	public enum AccountType
	{
		/// <summary>
		/// Presents the built-in account (default)
		/// </summary>
		BuiltIn,

		/// <summary>
		/// Presents the OAth account (Facebook, Google, Microsoft, Twitter, LinkedIn)
		/// </summary>
		OAuth,

		/// <summary>
		/// Presents the Windows Active Directory account
		/// </summary>
		Windows
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available status of an user's account
	/// </summary>
	public enum AccountStatus
	{
		/// <summary>
		/// Presents the registered account (but not yet activate)
		/// </summary>
		Registered,

		/// <summary>
		/// Presents the activated account
		/// </summary>
		Activated,

		/// <summary>
		/// Presents the locked account
		/// </summary>
		Locked,

		/// <summary>
		/// Presents the disabled account
		/// </summary>
		Disabled
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available type of an OAuth's account
	/// </summary>
	public enum OAuthType
	{
		/// <summary>
		/// Presents the account that are authenticated by Facebook OAuth
		/// </summary>
		Facebook,

		/// <summary>
		/// Presents the account that are authenticated by Goole OAuth
		/// </summary>
		Google,

		/// <summary>
		/// Presents the account that are authenticated by Microsoft OAuth
		/// </summary>
		Microsoft,

		/// <summary>
		/// Presents the account that are authenticated by Twitter OAuth
		/// </summary>
		Twitter,

		/// <summary>
		/// Presents the account that are authenticated by LinkedIn OAuth
		/// </summary>
		LinkedIn
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available type of two-factors authentication
	/// </summary>
	public enum TwoFactorsAuthenticationType
	{
		/// <summary>
		/// Presents the authenticator app like Google Authenticator, Microsoft Authenticator
		/// </summary>
		App,

		/// <summary>
		/// Presents the complex integrated SMS
		/// </summary>
		SMS,

		/// <summary>
		/// Presents the simple mobile phone number
		/// </summary>
		Phone
	}
}