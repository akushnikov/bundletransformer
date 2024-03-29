

   ----------------------------------------------------------------------
             README file for Bundle Transformer: Clean-css 1.9.77

   ----------------------------------------------------------------------

      Copyright (c) 2012-2015 Andrey Taritsyn - http://www.taritsyn.ru


   ===========
   DESCRIPTION
   ===========
   BundleTransformer.CleanCss contains one minifier-adapter for
   minification of CSS-code - `CleanCssMinifier`. `CleanCssMinifier` is
   based on the Clean-css (http://github.com/jakubpawlowicz/clean-css)
   version 3.4.5.

   As a JS-engine is used the JavaScript Engine Switcher library
   (http://github.com/Taritsyn/JavaScriptEngineSwitcher). For correct
   working of this module is recommended to install the following
   NuGet packages: JavaScriptEngineSwitcher.Msie or
   JavaScriptEngineSwitcher.V8.

   =============
   RELEASE NOTES
   =============
   Added support of Clean-css version 3.4.5.

   ====================
   POST-INSTALL ACTIONS
   ====================
   For correct working of this module is recommended to install the
   following NuGet packages: JavaScriptEngineSwitcher.Msie or
   JavaScriptEngineSwitcher.V8. After package is installed, need set a
   name of JavaScript engine (for example, `MsieJsEngine`) to the `name`
   attribute of `/configuration/bundleTransformer/clean/jsEngine`
   configuration element.

   To make `CleanCssMinifier` is the default CSS-minifier, you need
   to make changes to the Web.config file. In the `defaultMinifier`
   attribute of `\configuration\bundleTransformer\core\css` element must
   be set value equal to `CleanCssMinifier`.

   =============
   DOCUMENTATION
   =============
   See documentation on CodePlex -
   http://bundletransformer.codeplex.com/documentation