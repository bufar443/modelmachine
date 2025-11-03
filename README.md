"""
pandas>=1.5.0
scikit-learn>=1.2.0
matplotlib>=3.6.0
seaborn>=0.12.0
scapy>=2.4.5
elasticsearch>=8.0.0
numpy>=1.21.0
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import sniff, IP, TCP, UDP
import threading
from collections import Counter
import warnings
from datetime import datetime
import time
warnings.filterwarnings('ignore')

class NetworkTrafficAnalyzer:
    def __init__(self):
        self.features = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised',
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate'
        ]
        
        self.models = {}
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
    def preprocess_data(self, df):
        """Предобработка сетевых данных"""
        df_processed = df.copy()

        categorical_columns = ['protocol_type', 'service', 'flag']
        for col in categorical_columns:
            if col in df_processed.columns:
                self.label_encoders[col] = LabelEncoder()
                df_processed[col] = self.label_encoders[col].fit_transform(
                    df_processed[col].astype(str)
                )

        df_processed = df_processed.fillna(0)
        
        return df_processed
    
    def train_anomaly_detection(self, X, contamination=0.1):
        """Обучение модели обнаружения аномалий"""
        X_scaled = self.scaler.fit_transform(X)
        
        iso_forest = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        
        iso_forest.fit(X_scaled)
        self.models['anomaly'] = iso_forest
        print(" Модель обнаружения аномалий обучена")
        return iso_forest
    
    def predict_anomalies(self, X):
        """Предсказание аномалий"""
        if 'anomaly' not in self.models:
            raise ValueError("Модель аномалий не обучена!")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.models['anomaly'].predict(X_scaled)

        return [0 if x == 1 else 1 for x in predictions]

class TrafficGenerator:
    @staticmethod
    def generate_normal_traffic(n_samples=1000):
        """Генерация нормального сетевого трафика"""
        np.random.seed(42)
        
        data = {
            'duration': np.random.exponential(10, n_samples),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_samples),
            'service': np.random.choice(['http', 'smtp', 'ftp', 'ssh'], n_samples),
            'flag': np.random.choice(['SF', 'S0', 'REJ'], n_samples),
            'src_bytes': np.random.poisson(500, n_samples),
            'dst_bytes': np.random.poisson(300, n_samples),
            'count': np.random.poisson(5, n_samples),
            'serror_rate': np.random.beta(1, 20, n_samples),
            'rerror_rate': np.random.beta(1, 20, n_samples),
        }
        
        df = pd.DataFrame(data)
        df['label'] = 'normal'
        return df
    
    @staticmethod
    def generate_attack_traffic(n_samples=300):
        """Генерация атакующего трафика"""
        np.random.seed(42)

        ddos_data = {
            'duration': np.random.exponential(0.1, n_samples//3),
            'protocol_type': ['udp'] * (n_samples//3),
            'service': ['http'] * (n_samples//3),
            'flag': ['S0'] * (n_samples//3),
            'src_bytes': np.random.poisson(50, n_samples//3),
            'dst_bytes': np.random.poisson(1000, n_samples//3),
            'count': np.random.poisson(100, n_samples//3),
            'serror_rate': np.random.beta(10, 1, n_samples//3),
            'rerror_rate': np.random.beta(10, 1, n_samples//3),
        }

        scan_data = {
            'duration': np.random.exponential(0.5, n_samples//3),
            'protocol_type': ['tcp'] * (n_samples//3),
            'service': np.random.choice(['http', 'ssh', 'ftp'], n_samples//3),
            'flag': ['REJ'] * (n_samples//3),
            'src_bytes': np.random.poisson(100, n_samples//3),
            'dst_bytes': np.random.poisson(0, n_samples//3),
            'count': np.random.poisson(50, n_samples//3),
            'serror_rate': np.random.beta(15, 1, n_samples//3),
            'rerror_rate': np.random.beta(15, 1, n_samples//3),
        }

        brute_data = {
            'duration': np.random.exponential(2, n_samples//3),
            'protocol_type': ['tcp'] * (n_samples//3),
            'service': ['ssh'] * (n_samples//3),
            'flag': ['SF'] * (n_samples//3),
            'src_bytes': np.random.poisson(80, n_samples//3),
            'dst_bytes': np.random.poisson(60, n_samples//3),
            'count': np.random.poisson(20, n_samples//3),
            'serror_rate': np.random.beta(5, 1, n_samples//3),
            'rerror_rate': np.random.beta(5, 1, n_samples//3),
        }
        
        ddos_df = pd.DataFrame(ddos_data)
        scan_df = pd.DataFrame(scan_data)
        brute_df = pd.DataFrame(brute_data)
        
        ddos_df['label'] = 'ddos'
        scan_df['label'] = 'port_scan'
        brute_df['label'] = 'brute_force'
        
        return pd.concat([ddos_df, scan_df, brute_df], ignore_index=True)

class RealTimeMonitor:
    def __init__(self, analyzer, interface=None):
        self.analyzer = analyzer
        self.interface = interface
        self.packet_buffer = []
        self.is_monitoring = False
        self.stats = Counter()
        self.alert_count = 0
        
    def packet_handler(self, packet):
        """Обработчик пакетов для реального времени"""
        try:
            if IP in packet:
                features = self.extract_features(packet)
                self.packet_buffer.append(features)
    
                if len(self.packet_buffer) >= 50:
                    self.analyze_buffer()
                    
        except Exception as e:
            print(f"Ошибка обработки пакета: {e}")
    
    def extract_features(self, packet):
        """Извлечение features из сетевого пакета"""
        ip_layer = packet[IP]

        protocol = 'tcp' if TCP in packet else 'udp' if UDP in packet else 'other'

        service = 'other'
        if TCP in packet:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                service = 'http'
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                service = 'ssh'
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                service = 'ftp'
        
        features = {
            'duration': 0,
            'protocol_type': protocol,
            'service': service,
            'flag': 'SF' if TCP in packet and packet[TCP].flags else 'OTHER',
            'src_bytes': len(packet),
            'dst_bytes': 0,
            'count': 1,
            'serror_rate': 0,
            'rerror_rate': 0,
        }
        
        return features
    
    def analyze_buffer(self):
        """Анализ накопленных пакетов"""
        if not self.packet_buffer:
            return
            
        try:
            df = pd.DataFrame(self.packet_buffer)
            df_processed = self.analyzer.preprocess_data(df)

            predictions = self.analyzer.predict_anomalies(df_processed)

            anomaly_count = sum(predictions)
            self.stats['total_packets'] += len(predictions)
            self.stats['anomalies'] += anomaly_count
            
            if anomaly_count > 10:  
                self.alert_count += 1
                self.trigger_alert(anomaly_count)
            
            print(f" Обработано пакетов: {len(predictions)}, Аномалий: {anomaly_count}")
            
        except Exception as e:
            print(f"Ошибка анализа: {e}")
        finally:
            self.packet_buffer = []
    
    def trigger_alert(self, anomaly_count):
        """Триггер оповещения об атаке"""
        alert_msg = f"""
         СЕТЕВАЯ АТАКА ОБНАРУЖЕНА 
        Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Аномальных пакетов: {anomaly_count}
        Всего оповещений: {self.alert_count}
        Вероятная атака: DDoS/Port Scan
        Рекомендуемые действия:
        - Проверить логи IDS
        - Увеличить мониторинг
        - Рассмотреть блокировку IP
        """
        print(alert_msg)
        

        self.save_alert_to_file(anomaly_count)
    
    def save_alert_to_file(self, anomaly_count):
        """Сохранение оповещения в файл (вместо ELK)"""
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'alert_level': 'HIGH',
            'anomaly_count': anomaly_count,
            'total_alerts': self.alert_count,
            'message': 'Network attack detected by ML model'
        }
        
        try:
            with open('security_alerts.json', 'a') as f:
                f.write(json.dumps(alert_data) + '\n')
        except Exception as e:
            print(f"Ошибка сохранения оповещения: {e}")
    
    def simulate_realtime_traffic(self, duration=60):
        """Симуляция реального трафика для демонстрации"""
        print(f" Запуск симуляции сетевого трафика на {duration} секунд...")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:

            simulated_packet = {
                'IP': type('IP', (), {'src': '192.168.1.1', 'dst': '192.168.1.2'})
            }
            
       
            if packet_count % 10 == 0:  
                features = {
                    'duration': 0.1,
                    'protocol_type': 'tcp',
                    'service': 'http',
                    'flag': 'S0', 
                    'src_bytes': 1500,
                    'dst_bytes': 0,
                    'count': 100,  
                    'serror_rate': 0.8,
                    'rerror_rate': 0.7,
                }
            else:
                features = {
                    'duration': 5.0,
                    'protocol_type': np.random.choice(['tcp', 'udp']),
                    'service': np.random.choice(['http', 'ssh', 'ftp']),
                    'flag': 'SF',
                    'src_bytes': np.random.poisson(500),
                    'dst_bytes': np.random.poisson(300),
                    'count': np.random.poisson(5),
                    'serror_rate': np.random.beta(1, 20),
                    'rerror_rate': np.random.beta(1, 20),
                }
            
            self.packet_buffer.append(features)
            packet_count += 1
      
            if len(self.packet_buffer) >= 20:
                self.analyze_buffer()
            
            time.sleep(0.1)  
        
        print(f" Симуляция завершена. Обработано пакетов: {packet_count}")

def visualize_results(all_traffic):
    """Визуализация результатов анализа"""
    plt.figure(figsize=(15, 10))
    plt.subplot(2, 2, 1)
    sns.countplot(data=all_traffic, x='label', hue='predicted_anomaly')
    plt.title('Распределение аномалий по типам трафика')
    plt.xticks(rotation=45)
 
    plt.subplot(2, 2, 2)
    anomaly_rate = all_traffic.groupby('label')['predicted_anomaly'].mean()
    anomaly_rate.plot(kind='bar', color=['green', 'red', 'orange', 'blue'])
    plt.title('Процент аномалий по типам трафика')
    plt.ylabel('Процент аномалий')

    plt.subplot(2, 2, 3)
    sns.boxplot(data=all_traffic, x='label', y='src_bytes')
    plt.title('Распределение исходных байт по типам трафика')
    plt.xticks(rotation=45)

    plt.subplot(2, 2, 4)
    numeric_cols = all_traffic.select_dtypes(include=[np.number]).columns
    correlation_matrix = all_traffic[numeric_cols].corr()
    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0)
    plt.title('Матрица корреляции признаков')
    
    plt.tight_layout()
    plt.show()
def main():
    print("ЗАПУСК СИСТЕМЫ АНАЛИЗА СЕТЕВОГО ТРАФИКА")
    print("=" * 50)

    analyzer = NetworkTrafficAnalyzer()
    traffic_gen = TrafficGenerator()

    print("\n Этап 1: Генерация тренировочных данных...")
    normal_traffic = traffic_gen.generate_normal_traffic(1000)
    attack_traffic = traffic_gen.generate_attack_traffic(300)
    all_traffic = pd.concat([normal_traffic, attack_traffic], ignore_index=True)
    
    print(f"   • Нормальный трафик: {len(normal_traffic)} записей")
    print(f"   • Атакующий трафик: {len(attack_traffic)} записей")
    print(f"   • Всего данных: {len(all_traffic)} записей")

    print("\n Этап 2: Предобработка данных...")
    X_processed = analyzer.preprocess_data(all_traffic.drop('label', axis=1))

    print("\n Этап 3: Обучение модели машинного обучения...")
    analyzer.train_anomaly_detection(X_processed)
    
    print("\n Этап 4: Тестирование модели...")
    predictions = analyzer.predict_anomalies(X_processed)
    all_traffic['predicted_anomaly'] = predictions

    print("\n Этап 5: Визуализация результатов...")
    visualize_results(all_traffic)
    
    print("\n СТАТИСТИКА ОБНАРУЖЕНИЯ АТАК:")
    print("=" * 40)
    for label in all_traffic['label'].unique():
        label_data = all_traffic[all_traffic['label'] == label]
        anomaly_rate = label_data['predicted_anomaly'].mean() * 100
        print(f"   • {label:12}: {len(label_data):4} записей, {anomaly_rate:5.1f}% аномалий")
    
    total_anomalies = sum(predictions)
    detection_rate = total_anomalies / len(attack_traffic) * 100
    print(f"\n   • Всего аномалий обнаружено: {total_anomalies}")
    print(f"   • Эффективность обнаружения: {detection_rate:.1f}%")
    
    print("\n Этап 6: Запуск реального мониторинга...")
    monitor = RealTimeMonitor(analyzer)
    
    monitor.simulate_realtime_traffic(duration=30)
    
    print("\n ФИНАЛЬНАЯ СТАТИСТИКА МОНИТОРИНГА:")
    print("=" * 40)
    print(f"   • Всего обработано пакетов: {monitor.stats['total_packets']}")
    print(f"   • Обнаружено аномалий: {monitor.stats['anomalies']}")
    print(f"   • Сгенерировано оповещений: {monitor.alert_count}")
    print(f"   • Файл с оповещениями: security_alerts.json")
    
    print("\n СИСТЕМА УСПЕШНО ЗАВЕРШИЛА РАБОТУ!")
    print(" Оповещения сохранены в формате JSON для интеграции с ELK Stack")

if __name__ == "__main__":
    import json
    main()



