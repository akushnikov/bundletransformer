﻿namespace BundleTransformer.Core.Transformers
{
	using System.Collections.Generic;
	using System.Text;
	using System.Web.Optimization;

	using Utilities;

	/// <summary>
	/// Transformer that responsible to output trace information
	/// </summary>
	public sealed class Tracer : IBundleTransform
	{
		/// <summary>
		/// Displays trace information
		/// </summary>
		/// <param name="context">Object BundleContext</param>
		/// <param name="response">Object BundleResponse</param>
		public void Process(BundleContext context, BundleResponse response)
		{
			var content = new StringBuilder();

			content.AppendLine("*************************************************************************************");
			content.AppendLine("* BUNDLE RESPONSE                                                                   *");
			content.AppendLine("*************************************************************************************");

			IEnumerable<BundleFile> responseFiles = response.Files;
			foreach (var responseFile in responseFiles)
			{
				content.AppendLine("  " + responseFile.IncludedVirtualPath);
			}

			content.AppendLine();

			content.AppendLine("*************************************************************************************");
			content.AppendLine("* BUNDLE COLLECTION                                                                 *");
			content.AppendLine("*************************************************************************************");
			BundleCollection bundles = context.BundleCollection;
			foreach (var bundle in bundles)
			{
				content.AppendFormatLine("-= {0} =-", bundle.Path);

				IEnumerable<BundleFile> bundleFiles = bundle.EnumerateFiles(context);
				foreach (var bundleFile in bundleFiles)
				{
					content.AppendLine("  " + bundleFile.IncludedVirtualPath);
				}

				content.AppendLine();
			}

			response.ContentType = "text/plain";
			response.Content = content.ToString();
		}
	}
}