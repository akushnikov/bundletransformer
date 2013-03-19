namespace BundleTransformer.Tests.SassAndScss.Translators
{
	using System;
	using System.Collections.Generic;
	using System.Web;

	using Moq;
	using NUnit.Framework;

	using BundleTransformer.Core;
	using BundleTransformer.Core.FileSystem;
	using BundleTransformer.SassAndScss.Configuration;
	using BundleTransformer.SassAndScss.Translators;

	[TestFixture]
	public class SassAndScssTranslatorTests
	{
		private const string STYLES_DIRECTORY_VIRTUAL_PATH = "/Content/";
		private const string STYLES_DIRECTORY_URL = "/Content/";

		private HttpContextBase _httpContext;
		private ICssRelativePathResolver _cssRelativePathResolver;
		private SassAndScssSettings _sassAndScssConfig;

		[TestFixtureSetUp]
		public void SetUp()
		{
			_httpContext = new Mock<HttpContextBase>().Object;
			_cssRelativePathResolver = new MockCssRelativePathResolver();
			_sassAndScssConfig = new SassAndScssSettings();
		}

		[Test]
		public void FillingOfSassDependenciesIsCorrect()
		{
			// Arrange
			var virtualFileSystemMock = new Mock<IVirtualFileSystemWrapper>();

			string testSassImportSassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSassAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testSassImportSassAssetVirtualPath))
				.Returns(@"$alt-bg-color: #CE4DD6

.translators #sass
	background-color: $alt-bg-color
	border-color: $alt-bg-color

@import ""TestSassImport.Sub1.sass"", 'TestSassImport.Sub2', TestSassImport.Sub3
@import ""TestSassImport.Sub4""")
				;


			string testSassImportScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportScssAssetVirtualPath))
				.Returns(false)
				;


			string testSassImportSub1SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestSassImport.Sub1.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub1SassAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testSassImportSub1SassAssetVirtualPath))
				.Returns(@"$bg-color: brown

.translators #sass
	background-color: $bg-color")
				;


			string testSassImportSub1ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.Sub1.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub1ScssAssetVirtualPath))
				.Returns(false)
				;


			string testSassImportSub2SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.Sub2.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub2SassAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testSassImportSub2SassAssetVirtualPath))
				.Returns(@"$border-color: green

.translators #sass
	border-color: $border-color")
				;


			string testSassImportSub2ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.Sub2.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub2ScssAssetVirtualPath))
				.Returns(false)
				;


			string testSassImportSub3SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.Sub3.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub3SassAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testSassImportSub3SassAssetVirtualPath))
				.Returns(@"$font-style: italic

.translators #sass
	font-style: $font-style")
				;


			string testSassImportSub3ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.Sub3.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub3ScssAssetVirtualPath))
				.Returns(false)
				;


			string testSassImportSub4ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.Sub4.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub4ScssAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testSassImportSub4ScssAssetVirtualPath))
				.Returns(@".translators #sass
{
	border-style: dashed;
}")
				;


			string testSassImportSub4SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, 
				"TestSassImport.Sub4.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testSassImportSub4SassAssetVirtualPath))
				.Returns(false)
				;


			IVirtualFileSystemWrapper virtualFileSystemWrapper = virtualFileSystemMock.Object;

			var sassAndScssTranslator = new SassAndScssTranslator(_httpContext, virtualFileSystemWrapper, 
				_cssRelativePathResolver, _sassAndScssConfig);

			const string assetContent = @"$bg-color: #7AC0DA
$caption-color: #FFFFFF

@mixin visible
	display: block

@mixin rounded-corners($radius)
	border-radius: $radius
	-webkit-border-radius: $radius
	-moz-border-radius: $radius

.translators #sass
	float: left
	@include visible
	padding: 0.2em 0.5em 0.2em 0.5em
	background-color: $bg-color
	color: $caption-color
	font-weight: bold
	border: 1px solid $bg-color
	@include rounded-corners(5px)

@import ""TestSassImport.sass""";
			string assetUrl = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH, "TestSass.sass");
			var virtualPathDependencies = new List<string>();

			// Act
			sassAndScssTranslator.FillDependencies(assetContent, assetUrl, virtualPathDependencies);

			// Assert
			Assert.AreEqual(5, virtualPathDependencies.Count);
			Assert.AreEqual(testSassImportSassAssetVirtualPath, virtualPathDependencies[0]);
			Assert.AreEqual(testSassImportSub1SassAssetVirtualPath, virtualPathDependencies[1]);
			Assert.AreEqual(testSassImportSub2SassAssetVirtualPath, virtualPathDependencies[2]);
			Assert.AreEqual(testSassImportSub3SassAssetVirtualPath, virtualPathDependencies[3]);
			Assert.AreEqual(testSassImportSub4ScssAssetVirtualPath, virtualPathDependencies[4]);
		}

		[Test]
		public void FillingOfScssDependenciesIsCorrect()
		{
			// Arrange
			var virtualFileSystemMock = new Mock<IVirtualFileSystemWrapper>();

			string testScssImportScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportScssAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testScssImportScssAssetVirtualPath))
				.Returns(@"$alt-bg-color: #CE4DD6;

.translators #scss
{
	background-color: $alt-bg-color;
	border-color: $alt-bg-color;
}

@import""TestScssImport.Sub1.scss"", 'TestScssImport.Sub2',""TestScssImport.Sub3.scss"";
@import ""TestScssImport.Sub4.sass"";")
				;


			string testScssImportSassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSassAssetVirtualPath))
				.Returns(false)
				;


			string testScssImportSub1ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub1.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub1ScssAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testScssImportSub1ScssAssetVirtualPath))
				.Returns(@"$bg-color: blue;

.translators #scss
{
	background-color: $bg-color;
}")
				;


			string testScssImportSub1SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub1.sass"); 
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub1SassAssetVirtualPath))
				.Returns(false)
				;


			string testScssImportSub2ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub2.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub2ScssAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testScssImportSub2ScssAssetVirtualPath))
				.Returns(@"$border-color: yellow;

.translators #scss
{
	border-color: $border-color;
}")
				;


			string testScssImportSub2SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub2.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub2SassAssetVirtualPath))
				.Returns(false)
				;


			string testScssImportSub3ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub3.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub3ScssAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testScssImportSub3ScssAssetVirtualPath))
				.Returns(@"$text-decoration: underline;

.translators #scss
{
	text-decoration: $text-decoration;
}")
				;


			string testScssImportSub3SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub3.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub3SassAssetVirtualPath))
				.Returns(false)
				;


			string testScssImportSub4SassAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub4.sass");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub4SassAssetVirtualPath))
				.Returns(true)
				;
			virtualFileSystemMock
				.Setup(fs => fs.GetFileTextContent(testScssImportSub4SassAssetVirtualPath))
				.Returns(@".translators #scss
	border-style: dotted")
				;


			string testScssImportSub4ScssAssetVirtualPath = Utils.CombineUrls(STYLES_DIRECTORY_VIRTUAL_PATH,
				"TestScssImport.Sub4.scss");
			virtualFileSystemMock
				.Setup(fs => fs.FileExists(testScssImportSub4ScssAssetVirtualPath))
				.Returns(false)
				;


			IVirtualFileSystemWrapper virtualFileSystemWrapper = virtualFileSystemMock.Object;

			var sassAndScssTranslator = new SassAndScssTranslator(_httpContext, virtualFileSystemWrapper,
				_cssRelativePathResolver, _sassAndScssConfig);

			const string assetContent = @"$bg-color: #7AC0DA;
$caption-color: #FFFFFF;

@mixin visible
{
	display: block;
}

@mixin rounded-corners ($radius: 5px)
{
	border-radius: $radius;
	-webkit-border-radius: $radius;
	-moz-border-radius: $radius;
}

.translators #scss
{
	float: left;
	@include visible;
	padding: 0.2em 0.5em 0.2em 0.5em;
	background-color: $bg-color;
	color: $caption-color;
	font-weight: bold;
	border: 1px solid $bg-color;
	@include rounded-corners(5px);
}

@import ""TestScssImport.scss"";";
			string assetUrl = Utils.CombineUrls(STYLES_DIRECTORY_URL, "TestScss.scss");
			var virtualPathDependencies = new List<string>();

			// Act
			sassAndScssTranslator.FillDependencies(assetContent, assetUrl, virtualPathDependencies);

			// Assert
			Assert.AreEqual(5, virtualPathDependencies.Count);
			Assert.AreEqual(testScssImportScssAssetVirtualPath, virtualPathDependencies[0]);
			Assert.AreEqual(testScssImportSub1ScssAssetVirtualPath, virtualPathDependencies[1]);
			Assert.AreEqual(testScssImportSub2ScssAssetVirtualPath, virtualPathDependencies[2]);
			Assert.AreEqual(testScssImportSub3ScssAssetVirtualPath, virtualPathDependencies[3]);
			Assert.AreEqual(testScssImportSub4SassAssetVirtualPath, virtualPathDependencies[4]);
		}

		[TestFixtureTearDown]
		public void TearDown()
		{
			_cssRelativePathResolver = null;
			_sassAndScssConfig = null;
		}

		private class MockCssRelativePathResolver : ICssRelativePathResolver
		{
			public string ResolveRelativePath(string basePath, string relativePath)
			{
				return Utils.CombineUrls(STYLES_DIRECTORY_URL, relativePath);
			}

			#region Not implemented methods
			public string ResolveComponentsRelativePaths(string content, string path)
			{
				throw new NotImplementedException();
			}

			public string ResolveImportsRelativePaths(string content, string path)
			{
				throw new NotImplementedException();
			}

			public string ResolveAllRelativePaths(string content, string path)
			{
				throw new NotImplementedException();
			}
			#endregion
		}
	}
}