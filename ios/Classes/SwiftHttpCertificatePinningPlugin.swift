import Flutter
import UIKit
import CryptoSwift
import Alamofire

import Flutter
import UIKit
import Alamofire
import CommonCrypto


//!NEW
public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {

    private var allowedFingerprints: [String]?

     static let sharedSession: Session = {
        return Session(serverTrustManager: nil) // Default, will be configured per request
    }()

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
        let instance = SwiftHttpCertificatePinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "check":
            if let args = call.arguments as? [String: Any] {
                self.check(args: args, flutterResult: result)
            } else {
                result(FlutterError(code: "Invalid Arguments", message: "Please specify arguments", details: nil))
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func check(args: [String: Any], flutterResult: @escaping FlutterResult) {
        guard let urlString = args["url"] as? String,
              let url = URL(string: urlString),
              let domain = url.host,  // Extract domain dynamically
              let headers = args["headers"] as? [String: String],
              let fingerprints = args["fingerprints"] as? [String] else {
            flutterResult(FlutterError(code: "Params incorrect", message: "Invalid parameters", details: nil))
            return
        }

        self.allowedFingerprints = fingerprints

        let serverTrustManager = ServerTrustManager(
            evaluators: [
                domain: CustomServerTrustEvaluator(allowedFingerprints: fingerprints)
            ]
        )

        let session = SwiftHttpCertificatePinningPlugin.sharedSession
        session.sessionConfiguration.timeoutIntervalForRequest = 60
        session.request(urlString, method: .get, headers: HTTPHeaders(headers))
            .validate()
            .response { response in
                switch response.result {
                case .success:
                    flutterResult("CONNECTION_SECURE")
                case .failure(let error):
                    flutterResult(FlutterError(code: "CONNECTION_NOT_SECURE", message: error.localizedDescription, details: nil))
                }
            }
    }
}

class CustomServerTrustEvaluator: ServerTrustEvaluating {
    private let allowedFingerprints: [String]

    init(allowedFingerprints: [String]) {
        self.allowedFingerprints = allowedFingerprints
    }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        guard let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            throw AFError.serverTrustEvaluationFailed(reason: .noCertificatesFound)
        }

        let serverCertData = SecCertificateCopyData(serverCertificate) as Data
        let serverCertSha256 = serverCertData.sha256().toHexString()

       if !allowedFingerprints.contains(serverCertSha256) {
            throw AFError.serverTrustEvaluationFailed(
                reason: .certificatePinningFailed(
                    host: host,
                    trust: trust,
                    pinnedCertificates: [],
                    serverCertificates: [serverCertificate]
                )
            )
       }
    }
}

extension Data {
    func sha256() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &digest) }
        return Data(digest)
    }

    func toHexString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

//! OLD
// public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {

//     let manager = Alamofire.Session.default
//     var fingerprints: Array<String>?
//     var flutterResult: FlutterResult?

//     public static func register(with registrar: FlutterPluginRegistrar) {
//         let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
//         let instance = SwiftHttpCertificatePinningPlugin()
//         registrar.addMethodCallDelegate(instance, channel: channel)
//     }

//     public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
//         switch (call.method) {
//             case "check":
//                 if let _args = call.arguments as? Dictionary<String, AnyObject> {
//                     self.check(call: call, args: _args, flutterResult: result)
//                 } else {
//                     result(
//                         FlutterError(
//                             code: "Invalid Arguments",
//                             message: "Please specify arguments",
//                             details: nil)
//                     )
//                 }
//                 break
//         default:
//             result(FlutterMethodNotImplemented)
//         }
//     }

//     public func check(
//         call: FlutterMethodCall,
//         args: Dictionary<String, AnyObject>,
//         flutterResult: @escaping FlutterResult
//     ){
//         guard let urlString = args["url"] as? String,
//               let headers = args["headers"] as? Dictionary<String, String>,
//               let fingerprints = args["fingerprints"] as? Array<String>,
//               let type = args["type"] as? String
//         else {
//             flutterResult(
//                 FlutterError(
//                     code: "Params incorrect",
//                     message: "Les params sont incorrect",
//                     details: nil
//                 )
//             )
//             return
//         }

//         self.fingerprints = fingerprints

//         var timeout = 60
//         if let timeoutArg = args["timeout"] as? Int {
//             timeout = timeoutArg
//         }
        
//         let manager = Alamofire.Session(
//             configuration: URLSessionConfiguration.default
//         )
        
//         var resultDispatched = false;
        
//         manager.session.configuration.timeoutIntervalForRequest = TimeInterval(timeout)
        
//         manager.request(urlString, method: .get, parameters: headers).validate().responseJSON() { response in
//             switch response.result {
//                 case .success:
//                     break
//             case .failure(let error):
//                 if (!resultDispatched) {
//                     flutterResult(
//                         FlutterError(
//                             code: "URL Format",
//                             message: error.localizedDescription,
//                             details: nil
//                         )
//                     )
//                }
                   
//                 break
//             }
            
//             // To retain
//             let _ = manager
//         }

//         manager.delegate.sessionDidReceiveChallenge = { session, challenge in
//             guard let serverTrust = challenge.protectionSpace.serverTrust, let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
//                 flutterResult(
//                     FlutterError(
//                         code: "ERROR CERT",
//                         message: "Invalid Certificate",
//                         details: nil
//                     )
//                 )
                
//                 return (.cancelAuthenticationChallenge, nil)
//             }

//             // Set SSL policies for domain name check
//             let policies: [SecPolicy] = [SecPolicyCreateSSL(true, (challenge.protectionSpace.host as CFString))]
//             SecTrustSetPolicies(serverTrust, policies as CFTypeRef)

//             // Evaluate server certificate
//             var result: SecTrustResultType = .invalid
//             SecTrustEvaluate(serverTrust, &result)
//             let isServerTrusted: Bool = (result == .unspecified || result == .proceed)

//             let serverCertData = SecCertificateCopyData(certificate) as Data
//             var serverCertSha = serverCertData.sha256().toHexString()

//             if(type == "SHA1"){
//                 serverCertSha = serverCertData.sha1().toHexString()
//             }

//             var isSecure = false
//             if var fp = self.fingerprints {
//                 fp = fp.compactMap { (val) -> String? in
//                     val.replacingOccurrences(of: " ", with: "")
//             }

//                 isSecure = fp.contains(where: { (value) -> Bool in
//                     value.caseInsensitiveCompare(serverCertSha) == .orderedSame
//                 })
//             }

//             if isServerTrusted && isSecure {
//                 flutterResult("CONNECTION_SECURE")
//                 resultDispatched = true
//             } else {
//                 flutterResult(
//                     FlutterError(
//                         code: "CONNECTION_NOT_SECURE",
//                         message: nil,
//                         details: nil
//                     )
//                 )
//                 resultDispatched = true
//             }

//             return (.cancelAuthenticationChallenge, nil)
//         }
//     }
// }
