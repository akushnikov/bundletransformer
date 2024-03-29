﻿namespace BundleTransformer.MicrosoftAjax.Configuration
{
	using System.Configuration;

	/// <summary>
	/// Common configuration settings of Microsoft Ajax Minifier
	/// </summary>
	public sealed class MicrosoftAjaxSettings : ConfigurationSection
	{
		/// <summary>
		/// Gets a configuration settings of Microsoft Ajax CSS-minifier
		/// </summary>
		[ConfigurationProperty("css")]
		public CssMinifierSettings CssMinifier
		{
			get { return (CssMinifierSettings)this["css"]; }
		}

		/// <summary>
		/// Gets a configuration settings of Microsoft Ajax JS-minifier
		/// </summary>
		[ConfigurationProperty("js")]
		public JsMinifierSettings JsMinifier
		{
			get { return (JsMinifierSettings)this["js"]; }
		}
	}
}