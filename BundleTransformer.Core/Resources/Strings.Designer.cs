﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.225
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace BundleTransformer.Core.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    public class Strings {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Strings() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("BundleTransformer.Core.Resources.Strings", typeof(Strings).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        public static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to These assets are not style sheets: {0}..
        /// </summary>
        public static string Assets_CssAssetsContainAssetsWithInvalidTypes {
            get {
                return ResourceManager.GetString("Assets_CssAssetsContainAssetsWithInvalidTypes", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Pure wildcard ignore patterns &apos;*&apos; and &apos;*.*&apos; are not supported..
        /// </summary>
        public static string Assets_InvalidIgnorePattern {
            get {
                return ResourceManager.GetString("Assets_InvalidIgnorePattern", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to These assets are not scripts: {0}..
        /// </summary>
        public static string Assets_JsAssetsContainAssetsWithInvalidTypes {
            get {
                return ResourceManager.GetString("Assets_JsAssetsContainAssetsWithInvalidTypes", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Can not convert value &apos;{0}&apos; of enumeration type &apos;{1}&apos; to value of enumeration type &apos;{2}&apos;..
        /// </summary>
        public static string Common_EnumValueConversionFailed {
            get {
                return ResourceManager.GetString("Common_EnumValueConversionFailed", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to File {0} not exist..
        /// </summary>
        public static string Common_FileNotExist {
            get {
                return ResourceManager.GetString("Common_FileNotExist", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to During instantiate an object of type &apos;{0}&apos; error occurred..
        /// </summary>
        public static string Common_InstanceCreationFailed {
            get {
                return ResourceManager.GetString("Common_InstanceCreationFailed", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid full type name. Format the string like &apos;Namespace.ClassName, AssemblyName&apos;..
        /// </summary>
        public static string Common_InvalidFullTypeName {
            get {
                return ResourceManager.GetString("Common_InvalidFullTypeName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Value cannot be empty..
        /// </summary>
        public static string Common_ValueIsEmpty {
            get {
                return ResourceManager.GetString("Common_ValueIsEmpty", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Value cannot be null..
        /// </summary>
        public static string Common_ValueIsNull {
            get {
                return ResourceManager.GetString("Common_ValueIsNull", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Default {0}-minifier not specified..
        /// </summary>
        public static string Configuration_DefaultMinifierNotSpecified {
            get {
                return ResourceManager.GetString("Configuration_DefaultMinifierNotSpecified", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to {0}-minifier with name &apos;{1}&apos; is not registered in configuration file..
        /// </summary>
        public static string Configuration_MinifierNotRegistered {
            get {
                return ResourceManager.GetString("Configuration_MinifierNotRegistered", resourceCulture);
            }
        }
    }
}
