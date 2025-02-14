import Flutter
import UIKit
import CryptoSwift
import Alamofire

public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {
    var fingerprints: [String]?
    var flutterResult: FlutterResult?
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
        let instance = SwiftHttpCertificatePinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "check":
            if let args = call.arguments as? [String: AnyObject] {
                self.check(call: call, args: args, flutterResult: result)
            } else {
                result(FlutterError(code: "Invalid Arguments", message: "Please specify arguments", details: nil))
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    public func check(call: FlutterMethodCall, args: [String: AnyObject], flutterResult: @escaping FlutterResult) {
        guard let urlString = args["url"] as? String,
              let headers = args["headers"] as? [String: String],
              let fingerprints = args["fingerprints"] as? [String],
              let type = args["type"] as? String else {
            flutterResult(FlutterError(code: "Params incorrect", message: "Invalid parameters", details: nil))
            return
        }
        
        self.fingerprints = fingerprints.map { $0.replacingOccurrences(of: " ", with: "") }
        
        let timeout = (args["timeout"] as? Int) ?? 60
        
        let evaluator = ServerTrustEvaluator { serverTrust, hostname in
            guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
                return .failure(.certificatePinningFailed)
            }
            
            let serverCertData = SecCertificateCopyData(serverCertificate) as Data
            let serverCertSha = (type == "SHA1") ? serverCertData.sha1().toHexString() : serverCertData.sha256().toHexString()
            
            if self.fingerprints?.contains(where: { $0.caseInsensitiveCompare(serverCertSha) == .orderedSame }) == true {
                return .success(())
            }
            return .failure(.certificatePinningFailed)
        }
        
        let session = Session(configuration: .default, serverTrustManager: ServerTrustManager(evaluators: [urlString: evaluator]))
        
        session.request(urlString, method: .get, headers: HTTPHeaders(headers))
            .validate()
            .responseJSON { response in
                switch response.result {
                case .success:
                    flutterResult("CONNECTION_SECURE")
                case .failure(let error):
                    flutterResult(FlutterError(code: "CONNECTION_NOT_SECURE", message: error.localizedDescription, details: nil))
                }
            }
    }
}

extension Data {
    func sha1() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        self.withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(self.count), &digest) }
        return Data(digest)
    }
    
    func sha256() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &digest) }
        return Data(digest)
    }
    
    func toHexString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
