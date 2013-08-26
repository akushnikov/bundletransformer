﻿namespace BundleTransformer.Core.Configuration
{
	using System.Configuration;

	/// <summary>
	/// Configuration settings of core
	/// </summary>
	public sealed class CoreSettings : ConfigurationSection
	{
		/// <summary>
		/// Gets or sets a flag for whether to enable tracing
		/// </summary>
		[ConfigurationProperty("enableTracing", DefaultValue = false)]
		public bool EnableTracing
		{
			get { return (bool)this["enableTracing"]; }
			set { this["enableTracing"] = value; }
		}

		/// <summary>
		/// Gets or sets list of JS-files with Microsoft-style extensions
		/// </summary>
		[ConfigurationProperty("jsFilesWithMicrosoftStyleExtensions", DefaultValue = "MicrosoftAjax.js,MicrosoftMvcAjax.js,MicrosoftMvcValidation.js,knockout-$version$.js")]
		public string JsFilesWithMicrosoftStyleExtensions
		{
			get { return (string)this["jsFilesWithMicrosoftStyleExtensions"]; }
			set { this["jsFilesWithMicrosoftStyleExtensions"] = value; }
		}

		/// <summary>
		/// Gets or sets flag, which makes the debug mode is dependent on 
		/// the value of the BundleTable.EnableOptimizations property
		/// </summary>
		[ConfigurationProperty("useEnableOptimizationsProperty", DefaultValue = true)]
		public bool UseEnableOptimizationsProperty
		{
			get { return (bool)this["useEnableOptimizationsProperty"]; }
			set { this["useEnableOptimizationsProperty"] = value; }
		}

		/// <summary>
		/// Gets configuration settings of processing CSS-assets
		/// </summary>
		[ConfigurationProperty("css")]
		public CssSettings Css
		{
			get { return this["css"] as CssSettings; }
		}

		/// <summary>
		/// Gets configuration settings of processing JS-assets
		/// </summary>
		[ConfigurationProperty("js")]
		public JsSettings Js
		{
			get { return this["js"] as JsSettings; }
		}
	}
}