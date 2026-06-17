import os
import json
import logging
import queue
import threading
import time
from typing import Callable, Dict, List, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("StreamingBroker")

# Global flag to check if Kafka is available
KAFKA_AVAILABLE = False
try:
    from kafka import KafkaProducer, KafkaConsumer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    logger.warning("kafka-python-ng package not found. Streaming will run in InMemory mode.")

class MessageBroker:
    """
    Unified Message Broker interface supporting both Apache Kafka and InMemory thread-safe message queues.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MessageBroker, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        # Determine mode
        self.bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        self.use_kafka = KAFKA_AVAILABLE and self._test_kafka_connection()
        
        if self.use_kafka:
            logger.info(f"Initializing MessageBroker in KAFKA mode using servers: {self.bootstrap_servers}")
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    acks='all',
                    retries=3,
                    request_timeout_ms=5000
                )
            except Exception as e:
                logger.error(f"Failed to create KafkaProducer: {e}. Falling back to InMemory mode.")
                self.use_kafka = False
        
        if not self.use_kafka:
            logger.info("Initializing MessageBroker in IN-MEMORY mode.")
            self.queues: Dict[str, queue.Queue] = {}
            self.subscribers: Dict[str, List[Callable[[Any], None]]] = {}
            self._active_listeners = []
            
        self._initialized = True

    def _test_kafka_connection(self) -> bool:
        """Helper to quickly test if Kafka is reachable."""
        try:
            # Short timeout test
            temp_producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                request_timeout_ms=2000,
                max_block_ms=2000
            )
            temp_producer.close()
            return True
        except Exception:
            logger.warning("Kafka cluster is unreachable. Defaulting to InMemory streaming fallback.")
            return False

    def publish(self, topic: str, message: Dict[str, Any]):
        """
        Publishes a message to a topic.
        """
        if self.use_kafka:
            try:
                future = self.producer.send(topic, message)
                # In development/simulated settings, we can block or send async
                # For high reliability, let's log potential failures
                def on_err(exc):
                    logger.error(f"Kafka publish error on topic {topic}: {exc}")
                future.add_errback(on_err)
            except Exception as e:
                logger.error(f"Exception publishing to Kafka topic {topic}: {e}")
        else:
            # InMemory fallback
            if topic not in self.queues:
                self.queues[topic] = queue.Queue()
            
            # Put the message in the queue
            self.queues[topic].put(message)
            
            # Immediately notify any active callbacks registered (to simulate push)
            if topic in self.subscribers:
                for callback in self.subscribers[topic]:
                    # Run callback in a separate thread so it doesn't block the publisher
                    threading.Thread(
                        target=self._safe_execute_callback, 
                        args=(callback, message), 
                        daemon=True
                    ).start()

    def _safe_execute_callback(self, callback: Callable[[Any], None], message: Any):
        try:
            callback(message)
        except Exception as e:
            logger.error(f"Error executing callback in broker: {e}")

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None], group_id: str = "default-group"):
        """
        Registers a callback that is executed whenever a message is published to the topic.
        This blocks in a background thread for Kafka, or registers a subscriber list for InMemory.
        """
        if self.use_kafka:
            def kafka_consume_loop():
                logger.info(f"Starting background consumer loop for Kafka topic: {topic}")
                consumer = None
                while True:
                    try:
                        consumer = KafkaConsumer(
                            topic,
                            bootstrap_servers=self.bootstrap_servers,
                            group_id=group_id,
                            auto_offset_reset='latest',
                            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                            consumer_timeout_ms=1000
                        )
                        break
                    except Exception as e:
                        logger.error(f"Kafka consumer connection failed for topic {topic}, retrying in 5s: {e}")
                        time.sleep(5)

                while True:
                    try:
                        for message in consumer:
                            callback(message.value)
                    except Exception as e:
                        logger.error(f"Error in Kafka consumer loop for {topic}: {e}")
                        time.sleep(1)

            t = threading.Thread(target=kafka_consume_loop, daemon=True)
            t.start()
        else:
            # InMemory fallback registration
            if topic not in self.subscribers:
                self.subscribers[topic] = []
            self.subscribers[topic].append(callback)
            logger.info(f"Registered InMemory subscriber callback for topic: {topic}")

    def consume_generator(self, topic: str, group_id: str = "default-group"):
        """
        Generator function to pull messages from a topic (useful for pull-based loops).
        """
        if self.use_kafka:
            consumer = None
            try:
                consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=self.bootstrap_servers,
                    group_id=group_id,
                    auto_offset_reset='latest',
                    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
                )
                for message in consumer:
                    yield message.value
            except Exception as e:
                logger.error(f"Kafka consume generator exception: {e}")
                time.sleep(2)
        else:
            if topic not in self.queues:
                self.queues[topic] = queue.Queue()
            
            q = self.queues[topic]
            while True:
                try:
                    # Non-blocking get with timeout to allow thread interruption
                    msg = q.get(timeout=1.0)
                    yield msg
                    q.task_done()
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"InMemory consume generator error: {e}")
                    time.sleep(1)
