//
//  main.m
//  Key
//
//  Created by Ralph Plawetzki on 08.02.24.
//

#import <Cocoa/Cocoa.h>

// the kServiceName must be the same as in the project settings > Keychain Sharing > Keychain Groups
static NSString * const kServiceName = @"Cryptomator";
static NSString * const password = @"highly_secret";
static NSString * const vault = @"_Zba09MU1wMK";

SecAccessControlRef createAccessControl(void) {
    SecAccessControlCreateFlags flags = kSecAccessControlUserPresence;
    
    SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlocked,
        flags,
        NULL // Ignore any error
    );
    
    return accessControl;
}

// Method to add an item to the keychain with access control
void addItemToKeychain(void) {
    // Create a dictionary of keychain attributes
    NSDictionary *keychainAttributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kServiceName,
        (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)createAccessControl(),
        (__bridge id)kSecAttrAccount: vault,
        (__bridge id)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding] // Convert password string to data
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)keychainAttributes, NULL);
    if (status == errSecSuccess) {
        NSLog(@"Item added to keychain successfully.");
    } else {
        NSLog(@"Error adding item to keychain. Status code: %d", (int)status);
    }
}

// Method to retrieve and display an item from the keychain
void displayItemFromKeychain(void) {
    // Create a dictionary of search attributes to find the item in the keychain
    NSDictionary *searchAttributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kServiceName,
        (__bridge id)kSecAttrAccount: vault,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    
    CFDictionaryRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchAttributes, (CFTypeRef *)&result);
    
    if (status == errSecSuccess && result != NULL) {
        NSDictionary *attributes = (__bridge_transfer NSDictionary *)result;
        
        // Extract and display the password from the attributes
        NSData *passwordData = attributes[(__bridge id)kSecValueData];
        NSString *password = [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];
        NSLog(@"Item found in keychain. Password: %@", password);
    } else if (status == errSecItemNotFound) {
        NSLog(@"No matching item found in the keychain.");
    } else {
        NSLog(@"Error retrieving item from keychain. Status code: %d", (int)status);
    }
}

void updateItemFromKeychain(void) {
    // Create a dictionary of search attributes to find the item in the keychain
    NSDictionary *searchAttributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kServiceName,
        (__bridge id)kSecAttrAccount: vault,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };

    CFDictionaryRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchAttributes, (CFTypeRef *)&result);
    if (status == errSecSuccess && result != NULL) {
        NSLog(@"Item found in keychain, updating it.");
        NSDictionary *changeAttributes = @{
            (__bridge id)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding]
        };
        status = SecItemUpdate((__bridge CFDictionaryRef)searchAttributes, (__bridge CFDictionaryRef)changeAttributes);
        NSLog(@"Updated. Status code: %d", (int)status);
    } else if (status == errSecItemNotFound) {
        NSLog(@"No matching item found in the keychain.");
    } else {
        NSLog(@"Error updating item in keychain. Status code: %d", (int)status);
    }
}

void deleteItemFromKeychain(void) {
    NSDictionary *searchAttributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kServiceName,
        (__bridge id)kSecAttrAccount: vault
    };
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)searchAttributes);
    if (status == errSecSuccess) {
        NSLog(@"Item deleted from keychain successfully.");
    } else if (status == errSecItemNotFound) {
        NSLog(@"No matching item found in the keychain.");
    } else {
        NSLog(@"Error deleting item from keychain. Status code: %d", (int)status);
    }
}


// Main function
int main(int argc, const char * argv[]) {
    @autoreleasepool {
        //addItemToKeychain();
        displayItemFromKeychain();
        //updateItemFromKeychain();
        //deleteItemFromKeychain();
    }
    return 0;
}
