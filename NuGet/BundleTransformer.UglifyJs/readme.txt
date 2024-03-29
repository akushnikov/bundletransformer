

   ----------------------------------------------------------------------
             README file for Bundle Transformer: UglifyJS 1.9.78
 
   ----------------------------------------------------------------------

      Copyright (c) 2012-2015 Andrey Taritsyn - http://www.taritsyn.ru


   ===========
   DESCRIPTION
   ===========
   BundleTransformer.UglifyJs contains one minifier-adapter for 
   minification of JS-code - `UglifyJsMinifier`. `UglifyJsMinifier` is 
   based on the Mihai Bazon's UglifyJS 
   (http://github.com/mishoo/UglifyJS2) version 2.5.0.
   
   As a JS-engine is used the JavaScript Engine Switcher library 
   (http://github.com/Taritsyn/JavaScriptEngineSwitcher). For correct 
   working of this module is recommended to install one of the following 
   NuGet packages: JavaScriptEngineSwitcher.Msie or 
   JavaScriptEngineSwitcher.V8.
   
   =============
   RELEASE NOTES
   =============
   1. Added support of UglifyJS version 2.5.0;
   2. In compression settings was changed a default value of
      `KeepFunctionArgs` property from `false` to `true`.
   
   ====================
   POST-INSTALL ACTIONS
   ====================
   For correct working of this module is recommended to install one of 
   the following NuGet packages: JavaScriptEngineSwitcher.Msie or 
   JavaScriptEngineSwitcher.V8. After package is installed, need set a 
   name of JavaScript engine (for example, `MsieJsEngine`) to the `name`
   attribute of `/configuration/bundleTransformer/uglify/jsEngine` 
   configuration element.   
   
   To make `UglifyJsMinifier` is the default JS-minifier, you need to 
   make changes to the Web.config file. In the `defaultMinifier` attribute 
   of `\configuration\bundleTransformer\core\js` element must be set 
   value equal to `UglifyJsMinifier`.
   
   =============
   DOCUMENTATION
   =============
   See documentation on CodePlex - 
   http://bundletransformer.codeplex.com/documentation