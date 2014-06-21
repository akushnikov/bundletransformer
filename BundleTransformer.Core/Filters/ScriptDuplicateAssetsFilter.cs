﻿namespace BundleTransformer.Core.Filters
{
	using System;
	using System.Collections.Generic;
	using System.Linq;

	using Assets;
	using Resources;

	/// <summary>
	/// Filter that responsible for removal of duplicate script assets
	/// </summary>
	public sealed class ScriptDuplicateAssetsFilter : IFilter
	{
		/// <summary>
		/// Removes a duplicate script assets
		/// </summary>
		/// <param name="assets">Set of script assets</param>
		/// <returns>Set of unique script assets</returns>
		public IList<IAsset> Transform(IList<IAsset> assets)
		{
			if (assets == null)
			{
				throw new ArgumentException(Strings.Common_ValueIsEmpty, "assets");
			}

			if (assets.Count == 0)
			{
				return assets;
			}

			var processedAssets = new List<IAsset>();

			foreach (var asset in assets)
			{
				string newAssetVirtualPath = Asset.RemoveAdditionalJsFileExtension(asset.VirtualPath);
				string newAssetVirtualPathInUppercase = newAssetVirtualPath.ToUpperInvariant();
				bool assetExist = processedAssets
					.Count(a =>
						Asset.RemoveAdditionalJsFileExtension(a.VirtualPath).ToUpperInvariant() == newAssetVirtualPathInUppercase
					) > 0;

				if (!assetExist)
				{
					processedAssets.Add(asset);
				}
			}

			return processedAssets;
		}
	}
}