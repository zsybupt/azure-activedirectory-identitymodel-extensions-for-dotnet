//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Threading;

namespace InjectBinarySecretToken
{
    /// <summary>
    /// A generic base class for IAsyncResult implementations
    /// that wraps a ManualResetEvent.
    /// </summary>
    abstract class AsyncResult : IAsyncResult
    {
        private readonly AsyncCallback _callback;
        private bool _endCalled;
        private Exception _exception;
        private readonly object _lock;
        private ManualResetEvent _manualResetEvent;

        protected AsyncResult(AsyncCallback callback, object state)
        {
            _callback = callback;
            AsyncState = state;
            _lock = new object();
        }

        public object AsyncState { get; }

        public WaitHandle AsyncWaitHandle
        {
            get
            {
                if (_manualResetEvent != null)
                    return _manualResetEvent;

                lock (_lock)
                {
                    if (_manualResetEvent == null)
                        _manualResetEvent = new ManualResetEvent(IsCompleted);
                }

                return _manualResetEvent;
            }
        }

        public bool IsCompleted { get; private set; }

        public bool CompletedSynchronously { get; private set; }

        // Call this version of complete when your asynchronous operation is complete.  This will update the state
        // of the operation and notify the callback.
        protected void Complete(bool completedSynchronously)
        {
            if (IsCompleted)
                // It is a bug to call Complete twice.
                throw new InvalidOperationException("Cannot call Complete twice");

            CompletedSynchronously = completedSynchronously;
            if (completedSynchronously)
            {
                // If we completedSynchronously, then there is no chance that the manualResetEvent was created so
                // we do not need to worry about a race condition.
                Debug.Assert(_manualResetEvent == null, "No ManualResetEvent should be created for a synchronous AsyncResult.");
                IsCompleted = true;
            }
            else
            {
                lock (_lock)
                {
                    IsCompleted = true;
                    if (_manualResetEvent != null)
                        _manualResetEvent.Set();
                }
            }

            // If the callback throws, there is a bug in the callback implementation
            _callback?.Invoke(this);
        }

        // Call this version of complete if you raise an exception during processing.  In addition to notifying
        // the callback, it will capture the exception and store it to be thrown during AsyncResult.End.
        protected void Complete(bool completedSynchronously, Exception exception)
        {
            _exception = exception;
            Complete(completedSynchronously);
        }

        // End should be called when the End function for the asynchronous operation is complete.  It
        // ensures the asynchronous operation is complete, and does some common validation.
        protected static TAsyncResult End<TAsyncResult>(IAsyncResult result)  where TAsyncResult : AsyncResult
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            if (!(result is TAsyncResult asyncResult))
                throw new ArgumentException("Invalid async result.", nameof(result));

            if (asyncResult._endCalled)
                throw new InvalidOperationException("Async object already ended.");

            asyncResult._endCalled = true;
            if (!asyncResult.IsCompleted)
                asyncResult.AsyncWaitHandle.WaitOne();

            if (asyncResult._manualResetEvent != null)
                asyncResult._manualResetEvent.Close();

            if (asyncResult._exception != null)
                throw asyncResult._exception;

            return asyncResult;
        }
    }

    //An AsyncResult that completes as soon as it is instantiated.
    class CompletedAsyncResult : AsyncResult
    {
        public CompletedAsyncResult(AsyncCallback callback, object state)
            : base(callback, state)
        {
            Complete(true);
        }

        public static void End(IAsyncResult result)
        {
            AsyncResult.End<CompletedAsyncResult>(result);
        }
    }

    //A strongly typed AsyncResult
    abstract class TypedAsyncResult<T> : AsyncResult
    {
        T _data;

        protected TypedAsyncResult(AsyncCallback callback, object state)
            : base(callback, state)
        {
        }

        public T Data => _data;

        protected void Complete(T data, bool completedSynchronously)
        {
            _data = data;
            Complete(completedSynchronously);
        }

        public static T End(IAsyncResult result)
        {
            TypedAsyncResult<T> typedResult = AsyncResult.End<TypedAsyncResult<T>>(result);
            return typedResult.Data;
        }
    }

    //A strongly typed AsyncResult that completes as soon as it is instantiated.
    class TypedCompletedAsyncResult<T> : TypedAsyncResult<T>
    {
        public TypedCompletedAsyncResult(T data, AsyncCallback callback, object state)
            : base(callback, state)
        {
            Complete(data, true);
        }

        public new static T End(IAsyncResult result)
        {
            if (!(result is TypedCompletedAsyncResult<T> completedResult))
                throw new ArgumentException("Invalid async result.", nameof(result));

            return TypedAsyncResult<T>.End(completedResult);
        }
    }
}
