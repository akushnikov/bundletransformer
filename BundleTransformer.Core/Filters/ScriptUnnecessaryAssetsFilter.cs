﻿namespace BundleTransformer.Core.Filters
{
	using System;
	using System.Collections.Generic;

	using Assets;
	using Resources;

	/// <summary>
	/// Filter that responsible for removal of unnecessary script assets
	/// </summary>
	public sealed class ScriptUnnecessaryAssetsFilter : UnnecessaryAssetsFilterBase
	{
		/// <summary>
		/// Constructs a instance of unnecessary script assets filter
		/// </summary>
		/// <param name="ignorePatterns">List of patterns of files and directories that
		/// should be ignored when processing</param>
		public ScriptUnnecessaryAssetsFilter(string[] ignorePatterns) : base(ignorePatterns)
		{ }


		/// <summary>
		/// Removes a unnecessary script assets
		/// </summary>
		/// <param name="assets">Set of script assets</param>
		/// <returns>Set of necessary script assets</returns>
		public override IList<IAsset> Transform(IList<IAsset> assets)
		{
			if (assets == null)
			{
				throw new ArgumentException(Strings.Common_ValueIsEmpty, "assets");
			}

			if (assets.Count == 0)
			{
				return assets;
			}

			if (_ignoreRegExps == null || _ignoreRegExps.Count == 0)
			{
				return assets;
			}

			var processedAssets = new List<IAsset>();

			foreach (var asset in assets)
			{
				string processedAssetVirtualPath = Asset.RemoveAdditionalJsFileExtension(asset.VirtualPath);
				if (!IsUnnecessaryAsset(processedAssetVirtualPath))
				{
					processedAssets.Add(asset);
				}
			}

			return processedAssets;
		}
	}
}