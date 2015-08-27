package thredds.crawlabledataset;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A basic implementation of {@link ThreddsS3Client}.
 *
 * @author cwardgar
 * @since 2015/08/22
 */
public class ThreddsS3ClientImpl implements ThreddsS3Client {
    private static final Logger logger = LoggerFactory.getLogger(ThreddsS3ClientImpl.class);

    private final AmazonS3Client s3Client;

    public ThreddsS3ClientImpl() {
        // Use HTTP, it's much faster
        this.s3Client = new AmazonS3Client();
        this.s3Client.setEndpoint("http://s3.amazonaws.com");
    }

    public ThreddsS3ClientImpl(AmazonS3Client s3Client) {
        this.s3Client = s3Client;
    }

    @Override
    public ObjectMetadata getObjectMetadata(S3URI s3uri) {
        try {
            ObjectMetadata metadata = s3Client.getObjectMetadata(s3uri.getBucket(), s3uri.getKey());
            logger.info(String.format("S3 Downloaded metadata '%s'", s3uri));
            return metadata;
        } catch (IllegalArgumentException e) {  // Thrown by getObjectMetadata() when key == null.
            logger.info(e.getMessage());
            return null;
        } catch (AmazonServiceException e) {
            if (e.getStatusCode() == HttpStatus.SC_NOT_FOUND) {
                logger.info(String.format(
                        "There is no S3 bucket '%s' that has key '%s'.", s3uri.getBucket(), s3uri.getKey()), e);
                return null;
            } else {
                throw e;
            }
        }
    }

    @Override
    public ObjectListing listObjects(S3URI s3uri) {
        ListObjectsRequest listObjectsRequest =
                new ListObjectsRequest().withBucketName(s3uri.getBucket()).withDelimiter(S3URI.S3_DELIMITER);

        if (s3uri.getKey() != null) {
            listObjectsRequest.setPrefix(s3uri.getKeyWithTrailingDelimiter());
        }

        try {
            ObjectListing objectListing = s3Client.listObjects(listObjectsRequest);
            logger.info(String.format("S3 Downloaded listing '%s'", s3uri));

            if (objectListing.getObjectSummaries().isEmpty() && objectListing.getCommonPrefixes().isEmpty()) {
                // There are no empty directories in a S3 hierarchy.
                logger.info(String.format("In bucket '%s', the key '%s' does not denote an existing virtual directory.",
                        s3uri.getBucket(), s3uri.getKey()));
                return null;
            } else {
                return objectListing;
            }
        } catch (AmazonServiceException e) {
            if (e.getStatusCode() == HttpStatus.SC_NOT_FOUND) {
                logger.info(String.format("No S3 bucket named '%s' exists.", s3uri.getBucket()), e);
                return null;
            } else {
                throw e;
            }
        }
    }

    @Override
    public File saveObjectToFile(S3URI s3uri, File file) throws IOException {
        try {
            s3Client.getObject(new GetObjectRequest(s3uri.getBucket(), s3uri.getKey()), file);
            logger.info(String.format("S3 Downloaded object '%s' to '%s'", s3uri, file));
            return file;
        } catch (IllegalArgumentException e) {  // Thrown by getObject() when key == null.
            logger.info(e.getMessage());
            return null;
        } catch (AmazonServiceException e) {
            if (e.getStatusCode() == HttpStatus.SC_NOT_FOUND) {
                logger.info(String.format(
                        "There is no S3 bucket '%s' that has key '%s'.", s3uri.getBucket(), s3uri.getKey()), e);
                return null;
            } else {
                throw e;
            }
        }
    }

    public static File createTempFile(S3URI s3uri) throws IOException {
        File file = Files.createTempFile("S3Object", s3uri.getBaseName()).toFile();
        file.deleteOnExit();
        return file;
    }
}
