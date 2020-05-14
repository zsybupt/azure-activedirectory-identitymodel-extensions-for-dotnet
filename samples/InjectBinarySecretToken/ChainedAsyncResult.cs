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

namespace InjectBinarySecretToken
{
    internal delegate IAsyncResult ChainedBeginHandler(TimeSpan timeout, AsyncCallback asyncCallback, object state);
    internal delegate void ChainedEndHandler(IAsyncResult result);

    class ChainedAsyncResult : AsyncResult
    {
        private static AsyncCallback s_begin1Callback = new AsyncCallback(Begin1Callback);
        private static AsyncCallback s_begin2Callback = new AsyncCallback(Begin2Callback);

        private ChainedBeginHandler _begin2;
        private ChainedEndHandler _end1;
        private ChainedEndHandler _end2;
        private TimeoutHelper _timeoutHelper;

        protected ChainedAsyncResult(TimeSpan timeout, AsyncCallback callback, object state)
            : base(callback, state)
        {
            _timeoutHelper = new TimeoutHelper(timeout);
        }

        public ChainedAsyncResult(TimeSpan timeout, AsyncCallback callback, object state, ChainedBeginHandler begin1, ChainedEndHandler end1, ChainedBeginHandler begin2, ChainedEndHandler end2)
            : base(callback, state)
        {
            _timeoutHelper = new TimeoutHelper(timeout);
            Begin(begin1, end1, begin2, end2);
        }

        protected void Begin(ChainedBeginHandler begin1, ChainedEndHandler end1, ChainedBeginHandler begin2, ChainedEndHandler end2)
        {
            _end1 = end1;
            _begin2 = begin2;
            _end2 = end2;

            IAsyncResult result = begin1(_timeoutHelper.RemainingTime(), s_begin1Callback, this);
            if (!result.CompletedSynchronously)
                return;

            if (Begin1Completed(result))
                Complete(true);
        }

        static void Begin1Callback(IAsyncResult result)
        {
            if (result.CompletedSynchronously)
                return;

            ChainedAsyncResult thisPtr = (ChainedAsyncResult)result.AsyncState;
            Exception completeException = null;

            bool completeSelf;
            try
            {
                completeSelf = thisPtr.Begin1Completed(result);
            }
            catch (Exception exception)
            {
                completeSelf = true;
                completeException = exception;
            }

            if (completeSelf)
                thisPtr.Complete(false, completeException);
        }

        bool Begin1Completed(IAsyncResult result)
        {
            _end1(result);
            result = _begin2(_timeoutHelper.RemainingTime(), s_begin2Callback, this);
            if (!result.CompletedSynchronously)
                return false;

            _end2(result);
            return true;
        }

        static void Begin2Callback(IAsyncResult result)
        {
            if (result.CompletedSynchronously)
                return;

            ChainedAsyncResult thisPtr = (ChainedAsyncResult)result.AsyncState;
            Exception completeException = null;

            try
            {
                thisPtr._end2(result);
            }
            catch (Exception exception)
            {
                completeException = exception;
            }

            thisPtr.Complete(false, completeException);
        }

        public static void End(IAsyncResult result)
        {
            AsyncResult.End<ChainedAsyncResult>(result);
        }
    }
}
