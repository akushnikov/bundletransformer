﻿namespace BundleTransformer.SassAndScss.Translators
{
	using System;
	using System.Collections.Generic;
	using System.IO;
	using System.Linq;
	using System.Text.RegularExpressions;
	using System.Web;

	using Core;
	using Core.Assets;
	using Core.FileSystem;
	using CoreStrings = Core.Resources.Strings;
	using Core.Resources;
	using Core.Translators;

	using Compilers;
	using Configuration;
	using Constants;
	
	/// <summary>
	/// Translator that responsible for translation of Sass- or SCSS-code to CSS-code
	/// </summary>
	public sealed class SassAndScssTranslator : TranslatorWithNativeMinificationBase
	{
		/// <summary>
		/// Name of output code type
		/// </summary>
		const string OUTPUT_CODE_TYPE = "CSS";

		/// <summary>
		/// CSS-file extension
		/// </summary>
		private const string CSS_FILE_EXTENSION = ".css";

		/// <summary>
		/// Regular expression for working with paths of imported Sass-files
		/// </summary>
		private static readonly Regex _importSassFilesRuleRegex =
			new Regex(@"@import\s*" +
				@"(?<urlList>((?<quote>'|"")([\w \-+.:,;/?&=%~#$@()]+)(\k<quote>)" + 
				@"|([\w\-+.:;/?&=%~#$@()]+))" +
				@"(,\s*((?<quote>'|"")([\w \-+.:,;/?&=%~#$@()]+)(\k<quote>)" +
				@"|([\w\-+.:;/?&=%~#$@()]+)))*)",
				RegexOptions.IgnoreCase | RegexOptions.Compiled);

		/// <summary>
		/// Regular expression for working with paths of imported SCSS-files
		/// </summary>
		private static readonly Regex _importScssFilesRuleRegex =
			new Regex(@"@import\s*" +
				@"(?<urlList>(?<quote>'|"")([\w \-+.:,;/?&=%~#$@()]+)(\k<quote>)" + 
				@"(,\s*(?<quote>'|"")([\w \-+.:,;/?&=%~#$@()]+)(\k<quote>))*)",
				RegexOptions.IgnoreCase | RegexOptions.Compiled);

		/// <summary>
		/// HTTP context
		/// </summary>
		private readonly HttpContextBase _httpContext;

		/// <summary>
		/// File system wrapper
		/// </summary>
		private readonly IFileSystemWrapper _fileSystemWrapper;

		/// <summary>
		/// Relative path resolver
		/// </summary>
		private readonly IRelativePathResolver _relativePathResolver;

		/// <summary>
		/// Sass- and SCSS-compiler
		/// </summary>
		private readonly SassAndScssCompiler _sassAndScssCompiler;


		/// <summary>
		/// Constructs instance of Sass- and SCSS-translator
		/// </summary>
		public SassAndScssTranslator()
			: this(new HttpContextWrapper(HttpContext.Current),
				BundleTransformerContext.Current.GetFileSystemWrapper(),
				BundleTransformerContext.Current.GetCommonRelativePathResolver(),
				BundleTransformerContext.Current.GetSassAndScssConfiguration())
		{ }

		/// <summary>
		/// Constructs instance of Sass- and SCSS-translator
		/// </summary>
		/// <param name="httpContext">Object HttpContext</param>
		/// <param name="fileSystemWrapper">File system wrapper</param>
		/// <param name="relativePathResolver">Relative path resolver</param>
		/// <param name="sassAndScssConfig">Configuration settings of Sass- and SCSS-translator</param>
		public SassAndScssTranslator(HttpContextBase httpContext, IFileSystemWrapper fileSystemWrapper,
			IRelativePathResolver relativePathResolver, SassAndScssSettings sassAndScssConfig)
		{
			_httpContext = httpContext;
			_fileSystemWrapper = fileSystemWrapper;
			_relativePathResolver = relativePathResolver;
			_sassAndScssCompiler = new SassAndScssCompiler();

			UseNativeMinification = sassAndScssConfig.UseNativeMinification;
		}

		
		/// <summary>
		/// Translates code of asset written on Sass or SCSS to CSS-code
		/// </summary>
		/// <param name="asset">Asset with code written on Sass or SCSS</param>
		/// <returns>Asset with translated code</returns>
		public override IAsset Translate(IAsset asset)
		{
			if (asset == null)
			{
				throw new ArgumentException(Strings.Common_ValueIsEmpty, "asset");
			}

			InnerTranslate(asset, NativeMinificationEnabled);

			return asset;
		}

		/// <summary>
		/// Translates code of assets written on Sass or SCSS to CSS-code
		/// </summary>
		/// <param name="assets">Set of assets with code written on Sass or SCSS</param>
		/// <returns>Set of assets with translated code</returns>
		public override IList<IAsset> Translate(IList<IAsset> assets)
		{
			if (assets == null)
			{
				throw new ArgumentException(CoreStrings.Common_ValueIsEmpty, "assets");
			}

			if (assets.Count == 0)
			{
				return assets;
			}

			var assetsToProcessing = assets.Where(a => a.AssetType == AssetType.Sass 
				|| a.AssetType == AssetType.Scss).ToList();
			if (assetsToProcessing.Count == 0)
			{
				return assets;
			}

			bool enableNativeMinification = NativeMinificationEnabled;

			foreach (var asset in assetsToProcessing)
			{
				InnerTranslate(asset, enableNativeMinification);
			}

			return assets;
		}

		private void InnerTranslate(IAsset asset, bool enableNativeMinification)
		{
			string assetTypeName = (asset.AssetType == AssetType.Scss) ? "SCSS" : "Sass";
			string newContent;
			string assetPath = asset.Path;
			var pathDependencies = new List<string>();

			try
			{
				newContent = asset.Content;
				FillDependencies(newContent, asset.Url, pathDependencies);

				newContent = _sassAndScssCompiler.Compile(newContent, assetPath, enableNativeMinification);
			}
			catch (FileNotFoundException)
			{
				throw;
			}
			catch (SassAndScssCompilingException e)
			{
				throw new AssetTranslationException(
					string.Format(CoreStrings.Translators_TranslationSyntaxError,
						assetTypeName, OUTPUT_CODE_TYPE, assetPath, e.Message));
			}
			catch (Exception e)
			{
				throw new AssetTranslationException(
					string.Format(CoreStrings.Translators_TranslationFailed,
						assetTypeName, OUTPUT_CODE_TYPE, assetPath, e.Message), e);
			}

			asset.Content = newContent;
			asset.Minified = enableNativeMinification;
			asset.RequiredFilePaths = pathDependencies;
		}

		/// <summary>
		/// Fills the list of Sass- and SCSS-files, that were added to a Sass- or SCSS-asset 
		/// by using the @import directive
		/// </summary>
		/// <param name="assetContent">Text content of Sass- or SCSS-asset</param>
		/// <param name="assetUrl">URL of Sass- or SCSS-asset file</param>
		/// <param name="pathDependencies">List of Sass- and SCSS-files, that were added to a 
		/// Sass- or SCSS-asset by using the @import directive</param>
		public void FillDependencies(string assetContent, string assetUrl, IList<string> pathDependencies)
		{
			string assetExtension = Path.GetExtension(assetUrl);
			if (!string.IsNullOrEmpty(assetExtension))
			{
				assetExtension = assetExtension.ToLowerInvariant();
			}
			else
			{
				assetExtension = FileExtension.Sass;
			}

			MatchCollection matches;
			if (FileExtensionHelper.IsSass(assetExtension))
			{
				matches = _importSassFilesRuleRegex.Matches(assetContent);
			}
			else
			{
				matches = _importScssFilesRuleRegex.Matches(assetContent);
			}
			
			foreach (Match match in matches)
			{
				if (match.Groups["urlList"].Success)
				{
					string urlListString = match.Groups["urlList"].Value;
					if (!string.IsNullOrWhiteSpace(urlListString))
					{
						urlListString = urlListString
							.Replace(@"""", string.Empty)
							.Replace("'", string.Empty)
							;

						List<string> urlList = Utils.ConvertToStringCollection(urlListString, ',', true).ToList();
						foreach (string url in urlList)
						{
							string importedAssetUrl = _relativePathResolver.ResolveRelativePath(
								assetUrl, url.Trim());
							string importedAssetPath = _httpContext.Server.MapPath(importedAssetUrl);
							string importedAssetExtension = Path.GetExtension(importedAssetUrl);
							bool importedAssetExists;
							string newImportedAssetUrl;
							string newImportedAssetPath;

							if (FileExtensionHelper.IsSass(importedAssetExtension)
								|| FileExtensionHelper.IsScss(importedAssetExtension))
							{
								newImportedAssetUrl = importedAssetUrl;
								newImportedAssetPath = importedAssetPath;
								importedAssetExists = _fileSystemWrapper.FileExists(newImportedAssetPath);

								if (!importedAssetExists)
								{
									newImportedAssetUrl = GetPartialAssetUrl(newImportedAssetUrl);
									newImportedAssetPath = _httpContext.Server.MapPath(newImportedAssetUrl);
									importedAssetExists = _fileSystemWrapper.FileExists(newImportedAssetPath);
								}

								if (importedAssetExists)
								{
									pathDependencies.Add(newImportedAssetPath);

									string importedAssetContent = _fileSystemWrapper.GetFileTextContent(
										newImportedAssetPath);
									FillDependencies(importedAssetContent, newImportedAssetUrl,
										pathDependencies);
								}
								else
								{
									throw new FileNotFoundException(
										string.Format(Strings.Common_FileNotExist, importedAssetPath));
								}
							}
							else if (!string.Equals(importedAssetExtension, CSS_FILE_EXTENSION,
								StringComparison.InvariantCultureIgnoreCase))
							{
								string newImportedAssetExtension = assetExtension;
								newImportedAssetUrl = importedAssetUrl + newImportedAssetExtension;
								newImportedAssetPath = _httpContext.Server.MapPath(newImportedAssetUrl);
								importedAssetExists = _fileSystemWrapper.FileExists(newImportedAssetPath);

								if (!importedAssetExists)
								{
									newImportedAssetUrl = GetPartialAssetUrl(newImportedAssetUrl);
									newImportedAssetPath = _httpContext.Server.MapPath(newImportedAssetUrl);
									importedAssetExists = _fileSystemWrapper.FileExists(newImportedAssetPath);
								}

								if (!importedAssetExists)
								{
									newImportedAssetExtension = FileExtensionHelper.IsSass(newImportedAssetExtension) ?
											FileExtension.Scss : FileExtension.Sass;
									newImportedAssetUrl = importedAssetUrl + newImportedAssetExtension;
									newImportedAssetPath = _httpContext.Server.MapPath(newImportedAssetUrl);

									importedAssetExists = _fileSystemWrapper.FileExists(newImportedAssetPath);
								}

								if (!importedAssetExists)
								{
									newImportedAssetUrl = GetPartialAssetUrl(newImportedAssetUrl);
									newImportedAssetPath = _httpContext.Server.MapPath(newImportedAssetUrl);
									importedAssetExists = _fileSystemWrapper.FileExists(newImportedAssetPath);
								}

								if (importedAssetExists)
								{
									pathDependencies.Add(newImportedAssetPath);

									string importedAssetContent = _fileSystemWrapper.GetFileTextContent(
										newImportedAssetPath);
									FillDependencies(importedAssetContent, newImportedAssetUrl, pathDependencies);
								}
								else
								{
									throw new FileNotFoundException(
										string.Format(Strings.Common_FileNotExist, importedAssetPath));
								}
							}
						}
					}
				}
			}
		}

		/// <summary>
		/// Gets a partial asset url
		/// </summary>
		/// <param name="assetUrl">URL of asset file</param>
		/// <returns>URL of partial asset file</returns>
		private static string GetPartialAssetUrl(string assetUrl)
		{
			string partialAssetUrl = Utils.CombineUrls(
				Utils.ProcessBackSlashesInUrl(Path.GetDirectoryName(assetUrl)),
				"_" + Path.GetFileName(assetUrl)
			);

			return partialAssetUrl;
		}
	}
}
