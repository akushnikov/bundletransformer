﻿namespace BundleTransformer.SassAndScss.Configuration
{
	using System;
	using System.Configuration;

	using Core.Configuration;

	/// <summary>
	/// Configuration context extensions
	/// </summary>
	public static class ConfigurationContextExtensions
	{
		/// <summary>
		/// Configuration settings of Sass- and SCSS-translator
		/// </summary>
		private static readonly Lazy<SassAndScssSettings> _sassAndScssConfig =
			new Lazy<SassAndScssSettings>(() => (SassAndScssSettings)ConfigurationManager.GetSection("bundleTransformer/sassAndScss"));

		/// <summary>
		/// Gets a Sass- and SCSS-translator configuration settings
		/// </summary>
		/// <param name="context">Configuration context</param>
		/// <returns>Configuration settings of Sass- and SCSS-translator</returns>
		public static SassAndScssSettings GetSassAndScssSettings(this IConfigurationContext context)
		{
			return _sassAndScssConfig.Value;
		}
	}
}