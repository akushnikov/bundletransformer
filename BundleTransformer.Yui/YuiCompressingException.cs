﻿namespace BundleTransformer.Yui
{
	using System;

	/// <summary>
	/// The exception that is thrown when a compressing of asset code by YUI Compressor for .Net is failed
	/// </summary>
	public class YuiCompressingException : Exception
	{
		/// <summary>
		/// Initializes a new instance of the BundleTransformer.Yui.YuiCompressingException class
		/// with a specified error message
		/// </summary>
		/// <param name="message">The message that describes the error</param>
		public YuiCompressingException(string message)
			: base(message)
		{ }

		/// <summary>
		/// Initializes a new instance of the BundleTransformer.Yui.YuiCompressingException class
		/// with a specified error message and a reference to the inner exception that is the cause of this exception
		/// </summary>
		/// <param name="message">The error message that explains the reason for the exception</param>
		/// <param name="innerException">The exception that is the cause of the current exception</param>
		public YuiCompressingException(string message, Exception innerException)
			: base(message, innerException)
		{ }
	}
}