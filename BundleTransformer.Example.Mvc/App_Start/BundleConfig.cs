﻿namespace BundleTransformer.Example.Mvc
{
	using System.Web.Optimization;

	using Core.Orderers;
	using Core.Transformers;

	public class BundleConfig
	{
		// For more information on Bundling, visit http://go.microsoft.com/fwlink/?LinkId=254725
		public static void RegisterBundles(BundleCollection bundles)
		{
			bundles.UseCdn = true;

			var cssTransformer = new CssTransformer();
			var jsTransformer = new JsTransformer();
			var nullOrderer = new NullOrderer();

			var commonStylesBundle = new Bundle("~/Bundles/CommonStyles");
			commonStylesBundle.Include(
				"~/Content/Fonts.css",
				"~/Content/Site.css",
				"~/Content/BundleTransformer.css",
				"~/AlternativeContent/css/TestCssComponentsPaths.css",
				"~/Content/themes/base/jquery.ui.core.css",
				"~/Content/themes/base/jquery.ui.theme.css",
				"~/Content/themes/base/jquery.ui.resizable.css",
				"~/Content/themes/base/jquery.ui.button.css",
				"~/Content/themes/base/jquery.ui.dialog.css",
				"~/Content/TestTranslators.css",
				"~/Content/less/TestLess.less",
				"~/Content/sass/TestSass.sass",
				"~/Content/scss/TestScss.scss");
			commonStylesBundle.Transforms.Add(cssTransformer);
			commonStylesBundle.Orderer = nullOrderer;

			bundles.Add(commonStylesBundle);

			var modernizrBundle = new Bundle("~/Bundles/Modernizr");
			modernizrBundle.Include("~/Scripts/modernizr-2.*");
			modernizrBundle.Transforms.Add(jsTransformer);
			modernizrBundle.Orderer = nullOrderer;

			bundles.Add(modernizrBundle);

			var jQueryBundle = new Bundle("~/Bundles/Jquery", 
				"http://ajax.aspnetcdn.com/ajax/jQuery/jquery-1.9.1.min.js");
			jQueryBundle.Include("~/Scripts/jquery-{version}.js");
			jQueryBundle.Transforms.Add(jsTransformer);
			jQueryBundle.Orderer = nullOrderer;
			jQueryBundle.CdnFallbackExpression = "window.jquery";

			bundles.Add(jQueryBundle);

			var commonScriptsBundle = new Bundle("~/Bundles/CommonScripts");
			commonScriptsBundle.Include("~/Scripts/MicrosoftAjax.js",
				"~/Scripts/jquery-ui-{version}.js",
				"~/Scripts/jquery.validate.js",
				"~/Scripts/jquery.validate.unobtrusive.js",
				"~/Scripts/jquery.unobtrusive-ajax.js",
				"~/Scripts/knockout-2.*",
				"~/Scripts/coffee/TestCoffeeScript.coffee",
				"~/Scripts/coffee/TestLiterateCoffeeScript.litcoffee",
				"~/Scripts/coffee/TestCoffeeScriptMarkdown.coffee.md",
				"~/Scripts/ts/TranslatorBadge.ts",
				"~/Scripts/ts/ColoredTranslatorBadge.ts",
				"~/Scripts/ts/TestTypeScript.ts");
			commonScriptsBundle.Transforms.Add(jsTransformer);
			commonScriptsBundle.Orderer = nullOrderer;

			bundles.Add(commonScriptsBundle);

			var jqueryUiStylesDirectoryBundle = new Bundle("~/Bundles/JqueryUiStylesDirectory");
			jqueryUiStylesDirectoryBundle.IncludeDirectory("~/Content/themes/base/", "*.css");
			jqueryUiStylesDirectoryBundle.Transforms.Add(new CssTransformer(
				new[] { "*.all.css", "jquery.ui.base.css" }));

			bundles.Add(jqueryUiStylesDirectoryBundle);

			var scriptsDirectoryBundle = new Bundle("~/Bundles/ScriptsDirectory");
			scriptsDirectoryBundle.IncludeDirectory("~/Scripts/", "*.js", true);
			scriptsDirectoryBundle.Transforms.Add(new JsTransformer(
				new[] { "*.all.js", "references.js" }));

			bundles.Add(scriptsDirectoryBundle);
		}
	}
}